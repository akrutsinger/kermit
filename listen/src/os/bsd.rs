//! macOS/FreeBSD/OpenBSD packet listener on a `/dev/bpf*` device with a cBPF filter.
//!
//! Type-checked for its targets but never run on real hardware yet, so the `listen` binary still
//! refuses to build for them (see `main.rs`).

use alloc::vec;
use alloc::vec::Vec;
use core::ffi::CStr;

use common::dbgprintln;
use rustix::fd::{AsRawFd, OwnedFd};
use rustix::fs::{Mode, OFlags, open};
use rustix::io::{Errno, read};

use crate::filter::SockFilter;
use crate::source::{ListenError, PacketSource};

// The typed errno is diagnostic-only (nothing branches on it), so it's logged here and erased to the
// payload-free marker (ADR-0003).
fn io_err(e: Errno) -> ListenError {
    dbgprintln!("io error: {e:?}");
    ListenError::Io
}

// tcpdump -dd "udp and src host 1.2.3.4"  (direction handled by ioctl)
pub static FILTER: [SockFilter; 8] = [
    SockFilter {
        code: 0x28,
        jt: 0,
        jf: 0,
        k: 0x0000000C,
    },
    SockFilter {
        code: 0x15,
        jt: 0,
        jf: 5,
        k: 0x00000800,
    },
    SockFilter {
        code: 0x30,
        jt: 0,
        jf: 0,
        k: 0x00000017,
    },
    SockFilter {
        code: 0x15,
        jt: 0,
        jf: 3,
        k: 0x00000011,
    },
    SockFilter {
        code: 0x20,
        jt: 0,
        jf: 0,
        k: 0x0000001A,
    },
    SockFilter {
        code: 0x15,
        jt: 0,
        jf: 1,
        k: 0x01020304,
    },
    SockFilter {
        code: 0x06,
        jt: 0,
        jf: 0,
        k: 0x00040000,
    },
    SockFilter {
        code: 0x06,
        jt: 0,
        jf: 0,
        k: 0x00000000,
    },
];

// BPF_WORDALIGN alignment differs:
//   macOS:           sizeof(int32_t) = 4
//   FreeBSD/OpenBSD: sizeof(long)    = pointer width
#[cfg(target_os = "macos")]
const BPF_ALIGNMENT: usize = 4;
#[cfg(any(target_os = "freebsd", target_os = "openbsd"))]
const BPF_ALIGNMENT: usize = size_of::<libc::c_long>();

#[inline]
fn word_align(x: usize) -> usize {
    (x + BPF_ALIGNMENT - 1) & !(BPF_ALIGNMENT - 1)
}

pub struct Source {
    fd: OwnedFd,
    buf: Vec<u8>,
    pos: usize,
    valid: usize,
}

/// `struct bpf_program` from `<net/bpf.h>`. Its layout is the same on every BSD, but libc only binds
/// it for some of them (not macOS).
#[repr(C)]
struct BpfProgram {
    bf_len: libc::c_uint,
    bf_insns: *const SockFilter,
}

/// `/dev/bpf<i>` as a C string, built in a stack buffer instead of a heap `String` (ADR-0004).
fn bpf_path(i: u8, buf: &mut [u8; 12]) -> &CStr {
    const PREFIX: &[u8] = b"/dev/bpf";
    buf.fill(0);
    buf[..PREFIX.len()].copy_from_slice(PREFIX);
    let mut len = PREFIX.len();
    let (hundreds, tens, ones) = (i / 100, i / 10 % 10, i % 10);
    if hundreds > 0 {
        buf[len] = b'0' + hundreds;
        len += 1;
    }
    if hundreds > 0 || tens > 0 {
        buf[len] = b'0' + tens;
        len += 1;
    }
    buf[len] = b'0' + ones;
    // At most 8 + 3 bytes are written, so the zeroed last byte is always a terminating NUL.
    match CStr::from_bytes_until_nul(buf) {
        Ok(path) => path,
        Err(_) => unreachable!("bpf_path always leaves a NUL in the buffer"),
    }
}

impl PacketSource for Source {
    type Filter = [SockFilter];
    // BPF hands back records sized by the runtime-discovered `BIOCGBLEN` buffer, so there's no true
    // compile-time bound; this is what the threaded runtime keeps, and it logs any truncation.
    const MAX_FRAME: usize = 2048;

    fn open(iface: Option<&str>) -> Result<Self, ListenError> {
        let iface = iface.ok_or(ListenError::NoIface)?;

        let mut fd = None;
        let mut path = [0u8; 12];
        for i in 0..=u8::MAX {
            match open(
                bpf_path(i, &mut path),
                OFlags::RDWR | OFlags::CLOEXEC,
                Mode::empty(),
            ) {
                Ok(f) => {
                    fd = Some(f);
                    break;
                }
                Err(Errno::BUSY | Errno::ACCESS | Errno::PERM) => continue,
                Err(e) => return Err(io_err(e)),
            }
        }
        let fd = fd.ok_or(ListenError::NoBpfDevice)?;
        let raw = fd.as_raw_fd();

        // SAFETY: `ifreq` is a plain C struct (a byte array plus a union of integers, addresses and
        // pointers), for which all-zero bytes are a valid value.
        let mut ifr: libc::ifreq = unsafe { core::mem::zeroed() };
        let name = iface.as_bytes();
        if name.len() >= ifr.ifr_name.len() {
            return Err(ListenError::IfaceNameTooLong);
        }
        for (i, &b) in name.iter().enumerate() {
            ifr.ifr_name[i] = b as libc::c_char;
        }
        // SAFETY: `BIOCSETIF` reads an `ifreq`; `ifr` is a valid, NUL-terminated one that lives
        // across the call.
        unsafe { ioctl_or_err(raw, libc::BIOCSETIF, (&raw mut ifr).cast()) }?;

        let on: u32 = 1;
        // SAFETY: `BIOCIMMEDIATE` reads a `u_int`; `on` is one and lives across the call.
        unsafe { ioctl_or_err(raw, libc::BIOCIMMEDIATE, (&raw const on).cast_mut().cast()) }?;

        // Inbound-only filtering: BIOCSSEESENT with 0 = don't return locally sent packets. macOS
        // only has this; FreeBSD documents it as obsolete-but-supported next to BIOCSDIRECTION
        // (which libc doesn't bind). OpenBSD has neither and filters with BIOCSDIRFILT instead.
        #[cfg(any(target_os = "macos", target_os = "freebsd"))]
        {
            let see_sent: u32 = 0;
            // SAFETY: `BIOCSSEESENT` reads a `u_int`; `see_sent` is one and lives across the call.
            unsafe {
                ioctl_or_err(
                    raw,
                    libc::BIOCSSEESENT,
                    (&raw const see_sent).cast_mut().cast(),
                )
            }?;
        }
        #[cfg(target_os = "openbsd")]
        todo!("OpenBSD inbound-only filter: BIOCSDIRFILT with BPF_DIRECTION_OUT");

        let mut blen: u32 = 0;
        // SAFETY: `BIOCGBLEN` writes a `u_int`; `blen` is one and lives across the call.
        unsafe { ioctl_or_err(raw, libc::BIOCGBLEN, (&raw mut blen).cast()) }?;

        Ok(Self {
            fd,
            buf: vec![0u8; blen as usize],
            pos: 0,
            valid: 0,
        })
    }

    fn attach_filter(&mut self, prog: &[SockFilter]) -> Result<(), ListenError> {
        // libc::bpf_program { bf_len: u_int, bf_insns: *mut bpf_insn }
        // `bpf_insn` has the same layout as our `SockFilter`.
        // Reject a program too long for `bf_len` rather than let its length wrap, as on Linux.
        let bf_len = u32::try_from(prog.len()).map_err(|_| io_err(Errno::INVAL))?;
        let fprog = BpfProgram {
            bf_len,
            bf_insns: prog.as_ptr(),
        };
        // SAFETY: `BIOCSETF` reads a `bpf_program`; `fprog` is one that lives across the call and
        // points at `bf_len` `#[repr(C)]` `SockFilter`s, which match the kernel's `bpf_insn`. The
        // kernel copies the program and never writes through `bf_insns`.
        unsafe {
            ioctl_or_err(
                self.fd.as_raw_fd(),
                libc::BIOCSETF,
                (&raw const fprog).cast_mut().cast(),
            )
        }
    }

    fn recv(&mut self) -> Result<&[u8], ListenError> {
        let hdr_size = size_of::<libc::bpf_hdr>();
        loop {
            if self.pos + hdr_size <= self.valid {
                // SAFETY: `pos + size_of::<bpf_hdr>() <= valid <= buf.len()`, so the read is in
                // bounds. `read_unaligned` because a `Vec<u8>` only guarantees byte alignment.
                let hdr = unsafe {
                    self.buf
                        .as_ptr()
                        .add(self.pos)
                        .cast::<libc::bpf_hdr>()
                        .read_unaligned()
                };
                let pkt_start = self.pos + hdr.bh_hdrlen as usize;
                let pkt_end = pkt_start + hdr.bh_caplen as usize;
                if pkt_end > self.valid {
                    dbgprintln!("listen: malformed bpf record, dropping rest of read");
                    self.pos = self.valid;
                    continue;
                }
                self.pos = word_align(pkt_end);
                return Ok(&self.buf[pkt_start..pkt_end]);
            }
            // Blocking read, so this parks the calling thread until records arrive. EINTR is
            // retried; everything else is a real error.
            self.valid = match read(&self.fd, &mut self.buf[..]) {
                Ok(n) => n,
                Err(Errno::INTR) => continue,
                Err(e) => return Err(io_err(e)),
            };
            self.pos = 0;
        }
    }
}

/// `ioctl(fd, req, arg)`, with failure logged and erased to `ListenError::Io` (ADR-0003).
///
/// # Safety
///
/// `arg` must point to a live value of the type `req` reads or writes.
unsafe fn ioctl_or_err(
    fd: i32,
    req: libc::c_ulong,
    arg: *mut libc::c_void,
) -> Result<(), ListenError> {
    // SAFETY: the caller guarantees `arg` matches what `req` expects; `fd` is just a number to the
    // kernel, and a bad one fails with `EBADF`.
    if unsafe { libc::ioctl(fd, req, arg) } < 0 {
        return Err(io_err(Errno::from_raw_os_error(common::errno())));
    }
    Ok(())
}

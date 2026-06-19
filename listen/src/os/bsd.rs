// TODO: rewrite for no_std — currently uses std::io, Vec, and format!().
// try_recv() needs O_NONBLOCK on the BPF fd + EAGAIN handling (similar to linux).

use std::io;
use std::os::fd::{AsRawFd, OwnedFd};

use rustix::fs::{Mode, OFlags, open};
use rustix::io::read;

use crate::filter::SockFilter;
use crate::source::{ListenError, PacketSource};

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
#[cfg(feature = "macos")]
const BPF_ALIGNMENT: usize = 4;
#[cfg(any(feature = "freebsd", feature = "openbsd"))]
const BPF_ALIGNMENT: usize = std::mem::size_of::<libc::c_long>();

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

impl PacketSource for Source {
    type Filter = [SockFilter];

    fn open(iface: Option<&str>) -> Result<Self, ListenError> {
        let iface = iface.ok_or(ListenError::NoIface)?;

        let mut fd = None;
        for i in 0..256 {
            let path = format!("/dev/bpf{}", i);
            match open(&path, OFlags::RDWR | OFlags::CLOEXEC, Mode::empty()) {
                Ok(f) => {
                    fd = Some(f);
                    break;
                }
                Err(rustix::io::Errno::BUSY) => continue,
                Err(rustix::io::Errno::ACCESS) | Err(rustix::io::Errno::PERM) => continue,
                Err(e) => return Err(ListenError::Io(std::io::Error::from(e).kind())),
            }
        }
        let fd = fd.ok_or(ListenError::NoBpfDevice)?;
        let raw = fd.as_raw_fd();

        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
        let name = iface.as_bytes();
        if name.len() >= ifr.ifr_name.len() {
            return Err(ListenError::IfaceNameTooLong);
        }
        for (i, &b) in name.iter().enumerate() {
            ifr.ifr_name[i] = b as libc::c_char;
        }
        ioctl_or_err(raw, libc::BIOCSETIF, &mut ifr as *mut _ as *mut _)?;

        let on: u32 = 1;
        ioctl_or_err(raw, libc::BIOCIMMEDIATE, &on as *const _ as *mut _)?;

        // Inbound-only filtering. macOS uses BIOCSSEESENT (0 = don't see sent);
        // FreeBSD/OpenBSD use BIOCSDIRECTION with BPF_D_IN.
        #[cfg(feature = "macos")]
        {
            let see_sent: u32 = 0;
            ioctl_or_err(raw, libc::BIOCSSEESENT, &see_sent as *const _ as *mut _)?;
        }
        #[cfg(any(feature = "freebsd", feature = "openbsd"))]
        {
            let direction: u32 = libc::BPF_D_IN as u32;
            ioctl_or_err(raw, libc::BIOCSDIRECTION, &direction as *const _ as *mut _)?;
        }

        let mut blen: u32 = 0;
        ioctl_or_err(raw, libc::BIOCGBLEN, &mut blen as *mut _ as *mut _)?;

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
        let fprog = libc::bpf_program {
            bf_len: prog.len() as u32,
            bf_insns: prog.as_ptr() as *mut _,
        };
        ioctl_or_err(
            self.fd.as_raw_fd(),
            libc::BIOCSETF,
            &fprog as *const _ as *mut _,
        )
    }

    fn try_recv(&mut self) -> Result<Option<&[u8]>, ListenError> {
        todo!("BPF non-blocking recv: open with O_NONBLOCK, map EAGAIN to Ok(None)")
    }

    fn recv(&mut self) -> Result<&[u8], ListenError> {
        loop {
            if self.pos < self.valid {
                let hdr_ptr = unsafe { self.buf.as_ptr().add(self.pos) } as *const libc::bpf_hdr;
                let (caplen, hdrlen) =
                    unsafe { ((*hdr_ptr).bh_caplen as usize, (*hdr_ptr).bh_hdrlen as usize) };
                let pkt_start = self.pos + hdrlen;
                let pkt_end = pkt_start + caplen;
                self.pos = word_align(pkt_end);
                return Ok(&self.buf[pkt_start..pkt_end]);
            }
            self.valid = read(&self.fd, &mut self.buf)
                .map_err(|e| ListenError::Io(std::io::Error::from(e).kind()))?;
            self.pos = 0;
        }
    }
}

fn ioctl_or_err(fd: i32, req: libc::c_ulong, arg: *mut libc::c_void) -> Result<(), ListenError> {
    let rc = unsafe { libc::ioctl(fd, req, arg) };
    if rc < 0 {
        Err(ListenError::Io(io::Error::last_os_error().kind()))
    } else {
        Ok(())
    }
}

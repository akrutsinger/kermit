use core::num::NonZeroU32;

use rustix::fd::{AsRawFd, OwnedFd};
use rustix::io::Errno;
use rustix::net::{AddressFamily, Protocol, RecvFlags, SocketFlags, SocketType, socket_with};

use crate::filter::SockFilter;
use crate::source::{ListenError, PacketSource};

const RECV_BUF_SIZE: usize = 2048;

// tcpdump -dd "inbound and udp and src host 1.2.3.4"
//
// Uses the Linux-specific SKF_AD_OFF+SKF_AD_PKTTYPE extension (k=0xfffff004) for the inbound check
// While this is super cool for Linux, it doesn't help our Windows (haha, of course) or BSD OSs.
pub static FILTER: [SockFilter; 10] = [
    SockFilter {
        code: 0x28,
        jt: 0,
        jf: 0,
        k: 0xfffff004,
    },
    SockFilter {
        code: 0x15,
        jt: 7,
        jf: 0,
        k: 0x00000004,
    },
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
        k: 0x0000001a,
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

pub struct Source {
    fd: OwnedFd,
    buf: [u8; RECV_BUF_SIZE],
}

impl PacketSource for Source {
    type Filter = [SockFilter];
    const MAX_FRAME: usize = RECV_BUF_SIZE;

    fn open(_iface: Option<&str>) -> Result<Self, ListenError> {
        let eth_p_all_be = NonZeroU32::new((libc::ETH_P_ALL as u16).to_be() as u32)
            .ok_or(ListenError::Io(Errno::INVAL))?;
        // Blocking socket: the threaded runtime dedicates a thread to recv, so
        // a blocking read is what we want (an async runtime would set NONBLOCK).
        let fd = socket_with(
            AddressFamily::PACKET,
            SocketType::RAW,
            SocketFlags::CLOEXEC,
            Some(Protocol::from_raw(eth_p_all_be)),
        )
        .map_err(ListenError::Io)?;

        // NOTE: Intentionally don't bind so we can listen on all interfaces.

        Ok(Self {
            fd,
            buf: [0u8; RECV_BUF_SIZE],
        })
    }

    fn attach_filter(&mut self, prog: &[SockFilter]) -> Result<(), ListenError> {
        let fprog = libc::sock_fprog {
            len: prog.len() as u16,
            filter: prog.as_ptr() as *mut _,
        };

        let rc = unsafe {
            libc::setsockopt(
                self.fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_ATTACH_FILTER,
                &fprog as *const _ as *const _,
                core::mem::size_of::<libc::sock_fprog>() as u32,
            )
        };

        if rc < 0 {
            return Err(ListenError::Io(Errno::from_raw_os_error(unsafe {
                *libc::__errno_location()
            })));
        }

        Ok(())
    }

    fn recv(&mut self) -> Result<&[u8], ListenError> {
        // Blocking socket, so this parks the calling thread until a frame
        // arrives. EINTR is retried; everything else is a real error.
        loop {
            match rustix::net::recv(&self.fd, &mut self.buf[..], RecvFlags::empty()) {
                Ok((n, _)) => return Ok(&self.buf[..n]),
                Err(Errno::INTR) => continue,
                Err(e) => return Err(ListenError::Io(e)),
            }
        }
    }
}

impl rustix::fd::AsRawFd for Source {
    fn as_raw_fd(&self) -> rustix::fd::RawFd {
        self.fd.as_raw_fd()
    }
}

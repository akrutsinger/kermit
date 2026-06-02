use std::io;
use std::num::NonZeroU32;
use std::os::fd::{AsRawFd, OwnedFd};

use rustix::net::{AddressFamily, Protocol, RecvFlags, SocketFlags, SocketType, socket_with};

use crate::filter::SockFilter;
use crate::source::PacketSource;

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
    buf: Vec<u8>,
    last_len: usize,
}

impl PacketSource for Source {
    type Filter = [SockFilter];

    fn open(_iface: Option<&str>) -> anyhow::Result<Self> {
        let eth_p_all: u16 = (libc::ETH_P_ALL as u16).to_be();
        let fd = socket_with(
            AddressFamily::PACKET,
            SocketType::RAW,
            SocketFlags::CLOEXEC,
            Some(Protocol::from_raw(
                NonZeroU32::new(eth_p_all as u32).unwrap(),
            )),
        )?;
        // Intentionally don't bind so we can listen on all interfaces.
        Ok(Self {
            fd,
            buf: vec![0u8; 2048],
            last_len: 0,
        })
    }

    fn attach_filter(&mut self, prog: &[SockFilter]) -> anyhow::Result<()> {
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
                std::mem::size_of::<libc::sock_fprog>() as u32,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error().into());
        }
        Ok(())
    }

    fn recv(&mut self) -> anyhow::Result<&[u8]> {
        let (n, _flags) = rustix::net::recv(&self.fd, &mut self.buf, RecvFlags::empty())?;
        self.last_len = n;
        Ok(&self.buf[..n])
    }
}

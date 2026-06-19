// TODO: rewrite for no_std — currently uses std::io, Vec, std::net, and std::ffi.
// try_recv() needs non-blocking mode (FIONBIO/ioctlsocket) + WSAEWOULDBLOCK mapped to Ok(None).
// ListenError::Io wraps rustix::io::Errno, not std::io::ErrorKind — all error conversions need fixing.

// Windows packet listener via SIO_RCVALL on a raw IPv4 socket.
//
// Caveats:
//   - IPv4 only. No L2 header: each recv() yields an IPv4 packet starting
//     at the IP header (no Ethernet preamble like Linux/BSDs).
//   - Captures both inbound and outbound traffic on the bound interface.
//   - Requires Administrator privileges.
//   - No kernel cBPF filter; we filter in userspace inside `recv`.
//
// The `iface` argument is the local IPv4 address to bind to (e.g. "192.168.1.5"), not a NIC name —
// Windows binds raw sockets by address.

use std::ffi::c_void;
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::windows::io::AsRawSocket;

use rustix::fd::OwnedFd;
use rustix::net::{
    AddressFamily, RecvFlags, SocketAddrAny, SocketFlags, SocketType, bind, socket_with,
};

use crate::source::{ListenError, PacketSource};

#[derive(Clone, Copy)]
pub struct Filter {
    pub protocol: u8,              // IPPROTO_*; 0 = match any
    pub src_addr: Option<[u8; 4]>, // big-endian octets; None = match any
}

pub static FILTER: Filter = Filter {
    protocol: 17, // UDP
    src_addr: Some([1, 2, 3, 4]),
};

const SIO_RCVALL: u32 = 0x98000001;
const RCVALL_ON: u32 = 1;

unsafe extern "system" {
    fn WSAIoctl(
        s: usize, // SOCKET
        dwIoControlCode: u32,
        lpvInBuffer: *const c_void,
        cbInBuffer: u32,
        lpvOutBuffer: *mut c_void,
        cbOutBuffer: u32,
        lpcbBytesReturned: *mut u32,
        lpOverlapped: *mut c_void,
        lpCompletionRoutine: *mut c_void,
    ) -> i32;
}

pub struct Source {
    fd: OwnedFd,
    buf: Vec<u8>,
    filter: Filter,
}

impl PacketSource for Source {
    type Filter = Filter;

    fn open(iface: Option<&str>) -> Result<Self, ListenError> {
        let addr_str = iface.ok_or(ListenError::NoIface)?;
        let ip: Ipv4Addr = addr_str.parse().map_err(|_| ListenError::InvalidAddr)?;

        // socket(AF_INET, SOCK_RAW, 0)  — protocol=None → 0 = IPPROTO_IP
        let fd = socket_with(
            AddressFamily::INET,
            SocketType::RAW,
            SocketFlags::empty(),
            None,
        )
        .map_err(|e| ListenError::Io(std::io::Error::from(e).kind()))?;

        let sa = SocketAddrAny::from(std::net::SocketAddr::V4(SocketAddrV4::new(ip, 0)));
        bind(&fd, &sa).map_err(|e| ListenError::Io(std::io::Error::from(e).kind()))?;

        let mut bytes_returned: u32 = 0;
        let on: u32 = RCVALL_ON;
        let rc = unsafe {
            WSAIoctl(
                fd.as_raw_socket() as usize,
                SIO_RCVALL,
                &on as *const _ as *const c_void,
                std::mem::size_of::<u32>() as u32,
                std::ptr::null_mut(),
                0,
                &mut bytes_returned,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if rc != 0 {
            return Err(ListenError::Io(io::Error::last_os_error().kind()));
        }

        Ok(Self {
            fd,
            buf: vec![0u8; 65536],
            filter: FILTER,
        })
    }

    fn attach_filter(&mut self, prog: &Filter) -> Result<(), ListenError> {
        self.filter = *prog;
        Ok(())
    }

    fn try_recv(&mut self) -> Result<Option<&[u8]>, ListenError> {
        todo!("Windows non-blocking recv: ioctlsocket FIONBIO, map WSAEWOULDBLOCK to Ok(None)")
    }

    fn recv(&mut self) -> Result<&[u8], ListenError> {
        loop {
            let (n, _flags) = rustix::net::recv(&self.fd, &mut self.buf, RecvFlags::empty())
                .map_err(|e| ListenError::Io(std::io::Error::from(e).kind()))?;
            // NLL doesn't let us return inside the loop while still borrowing self.buf
            // conditionally; check first, then re-borrow on return.
            if accept(&self.buf[..n], &self.filter) {
                return Ok(&self.buf[..n]);
            }
        }
    }
}

fn accept(pkt: &[u8], f: &Filter) -> bool {
    if pkt.len() < 20 || pkt[0] >> 4 != 4 {
        return false;
    }
    if f.protocol != 0 && pkt[9] != f.protocol {
        return false;
    }
    if let Some(want) = f.src_addr
        && pkt[12..16] != want
    {
        return false;
    }
    true
}

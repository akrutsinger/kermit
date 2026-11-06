//! Windows packet listener via `SIO_RCVALL` on a raw IPv4 socket, calling WinSock through
//! `windows-sys` directly (ADR-0002).
//!
//! Caveats:
//!   - IPv4 only. No L2 header: each recv() yields an IPv4 packet starting
//!     at the IP header (no Ethernet preamble like Linux/BSDs).
//!   - Captures both inbound and outbound traffic on the bound interface.
//!   - Requires Administrator privileges.
//!   - No kernel cBPF filter; we filter in userspace inside `recv`.
//!
//! The `iface` argument is the local IPv4 address to bind to (e.g. "192.168.1.5"), not a NIC name;
//! Windows binds raw sockets by address.
//!
//! Type-checked for Windows but never run there yet, so the `listen` binary still refuses to build
//! for it (see `main.rs`).

use alloc::vec;
use alloc::vec::Vec;
use core::ffi::c_void;
use core::net::Ipv4Addr;

use common::dbgprintln;
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, IN_ADDR, IN_ADDR_0, INVALID_SOCKET, IPPROTO_IP, RCVALL_ON, SIO_RCVALL, SOCK_RAW,
    SOCKADDR, SOCKADDR_IN, SOCKET, SOCKET_ERROR, WSADATA, WSAGetLastError, WSAIoctl, WSAStartup,
    bind, closesocket, recv, socket,
};

use crate::source::{ListenError, PacketSource};

// The largest IPv4 datagram; `SIO_RCVALL` hands back whole IP packets.
const RECV_BUF_SIZE: usize = 65535;

// The typed WSA error is diagnostic-only, so it's logged here and erased to the payload-free marker
// (ADR-0003).
fn wsa_err(what: &str) -> ListenError {
    // SAFETY: `WSAGetLastError` has no preconditions; it reads this thread's last WinSock error.
    let code = unsafe { WSAGetLastError() };
    dbgprintln!("{what} failed: WSA error {code}");
    ListenError::Io
}

#[derive(Clone, Copy)]
pub struct Filter {
    pub protocol: u8,              // IPPROTO_*; 0 = match any
    pub src_addr: Option<[u8; 4]>, // big-endian octets; None = match any
}

pub static FILTER: Filter = Filter {
    protocol: 17, // UDP
    src_addr: Some([1, 2, 3, 4]),
};

pub struct Source {
    sock: SOCKET,
    buf: Vec<u8>,
    filter: Filter,
}

impl Drop for Source {
    fn drop(&mut self) {
        // SAFETY: `self.sock` is a socket this `Source` opened and still owns, closed exactly once.
        unsafe { closesocket(self.sock) };
    }
}

impl PacketSource for Source {
    type Filter = Filter;
    const MAX_FRAME: usize = RECV_BUF_SIZE;

    fn open(iface: Option<&str>) -> Result<Self, ListenError> {
        let addr = iface.ok_or(ListenError::NoIface)?;
        let ip: Ipv4Addr = addr.parse().map_err(|_| ListenError::InvalidAddr)?;

        // WinSock must be initialized before any socket call. Startups are reference-counted, so
        // one per `open` is fine; it is never cleaned up because the socket lives for the process.
        let mut wsa = WSADATA::default();
        // SAFETY: `wsa` is a valid out-pointer for the `WSADATA` that `WSAStartup` fills in.
        let rc = unsafe { WSAStartup(0x0202, &mut wsa) };
        if rc != 0 {
            dbgprintln!("WSAStartup failed: {rc}");
            return Err(ListenError::Io);
        }

        // SAFETY: plain FFI call with constant arguments, after WinSock was initialized above.
        let sock = unsafe { socket(AF_INET.into(), SOCK_RAW, IPPROTO_IP) };
        if sock == INVALID_SOCKET {
            return Err(wsa_err("socket"));
        }
        // From here on `src` owns `sock` and closes it on every early return.
        let src = Self {
            sock,
            buf: vec![0u8; RECV_BUF_SIZE],
            filter: FILTER,
        };

        let sa = SOCKADDR_IN {
            sin_family: AF_INET,
            sin_port: 0,
            sin_addr: IN_ADDR {
                // `S_addr` is in network byte order, which is the octets' own order in memory.
                S_un: IN_ADDR_0 {
                    S_addr: u32::from_ne_bytes(ip.octets()),
                },
            },
            sin_zero: [0; 8],
        };
        // SAFETY: `sa` is a fully initialized `SOCKADDR_IN` that outlives the call, and `namelen`
        // is its exact size.
        let rc = unsafe {
            bind(
                src.sock,
                (&raw const sa).cast::<SOCKADDR>(),
                size_of::<SOCKADDR_IN>() as i32,
            )
        };
        if rc == SOCKET_ERROR {
            return Err(wsa_err("bind"));
        }

        let on = RCVALL_ON;
        let mut bytes_returned = 0u32;
        // SAFETY: the input buffer is `on`, valid for `size_of_val(&on)` bytes across the call; there
        // is no output buffer (null, length 0); `bytes_returned` is a valid out-pointer; and null
        // overlapped/completion arguments make this a synchronous call.
        let rc = unsafe {
            WSAIoctl(
                src.sock,
                SIO_RCVALL,
                (&raw const on).cast::<c_void>(),
                size_of_val(&on) as u32,
                core::ptr::null_mut(),
                0,
                &mut bytes_returned,
                core::ptr::null_mut(),
                None,
            )
        };
        if rc == SOCKET_ERROR {
            return Err(wsa_err("WSAIoctl(SIO_RCVALL)"));
        }

        Ok(src)
    }

    fn attach_filter(&mut self, prog: &Filter) -> Result<(), ListenError> {
        self.filter = *prog;
        Ok(())
    }

    fn recv(&mut self) -> Result<&[u8], ListenError> {
        loop {
            // SAFETY: `self.buf` is valid for writes of its whole length, which is `RECV_BUF_SIZE`
            // and so fits in `i32`.
            let n = unsafe { recv(self.sock, self.buf.as_mut_ptr(), self.buf.len() as i32, 0) };
            if n == SOCKET_ERROR {
                return Err(wsa_err("recv"));
            }
            let n = n as usize; // only `SOCKET_ERROR` is negative
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

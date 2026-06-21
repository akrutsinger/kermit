#[allow(dead_code)]
#[derive(Debug)]
pub enum ListenError {
    Io(rustix::io::Errno),
    NoIface,
    NoBpfDevice,
    IfaceNameTooLong,
    InvalidAddr,
}

impl core::fmt::Display for ListenError {
    fn fmt(&self, _f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        #[cfg(debug_assertions)]
        match self {
            ListenError::Io(errno) => write!(_f, "i/o error: {errno:?}")?,
            ListenError::NoIface => _f.write_str("interface name required")?,
            ListenError::NoBpfDevice => _f.write_str("no available /dev/bpf* device")?,
            ListenError::IfaceNameTooLong => _f.write_str("interface name too long")?,
            ListenError::InvalidAddr => _f.write_str("invalid IPv4 address")?,
        }
        Ok(())
    }
}

impl core::error::Error for ListenError {}

// Linux & BSDs share the cBPF instruction format (`[SockFilter]`). Windows
// has no kernel cBPF for raw IPv4 sockets, so it filters in userspace and
// uses its own filter shape.
pub trait PacketSource: Send + Sized {
    type Filter: ?Sized;

    // `iface` is optional on Linux (None = all interfaces). BSD BPF and
    // Windows SIO_RCVALL both require an explicit interface and will
    // return an error if None.
    fn open(iface: Option<&str>) -> Result<Self, ListenError>;

    fn attach_filter(&mut self, prog: &Self::Filter) -> Result<(), ListenError>;

    // Blocks until the next matching packet arrives. The returned slice borrows
    // from the source's internal buffer and is valid until the next call to
    // `recv`. The threaded runtime calls this from a dedicated recv thread; an
    // async runtime would instead use a non-blocking socket + readiness (see
    // the embassy seam).
    fn recv(&mut self) -> Result<&[u8], ListenError>;
}

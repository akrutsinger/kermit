// Linux & BSDs share the cBPF instruction format (`[SockFilter]`). Windows
// has no kernel cBPF for raw IPv4 sockets, so it filters in userspace and
// uses its own filter shape.
pub trait PacketSource: Send + Sized {
    type Filter: ?Sized;

    // `iface` is optional on Linux (None = all interfaces). BSD BPF and
    // Windows SIO_RCVALL both require an explicit interface and will
    // return an error if None.
    fn open(iface: Option<&str>) -> anyhow::Result<Self>;

    fn attach_filter(&mut self, prog: &Self::Filter) -> anyhow::Result<()>;

    // Blocks until the next matching packet arrives. The returned slice
    // borrows from the source's internal buffer and is valid until the
    // next call to `recv`.
    fn recv(&mut self) -> anyhow::Result<&[u8]>;
}

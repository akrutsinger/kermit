//! Bare-metal (`target_os = "none"`) packet source -- not yet implemented. What it captures from
//! (an Ethernet MAC, a radio, ...) depends on the board, which hasn't been chosen.

use crate::source::{ListenError, PacketSource};

/// No filter shape yet; it depends on what the board's capture hardware can do.
pub static FILTER: () = ();

pub struct Source;

impl PacketSource for Source {
    type Filter = ();
    // An untagged Ethernet frame without FCS; revisit once the board's capture hardware is known.
    const MAX_FRAME: usize = 1514;

    fn open(_iface: Option<&str>) -> Result<Self, ListenError> {
        todo!("bare-metal packet source, board-specific")
    }

    fn attach_filter(&mut self, _prog: &()) -> Result<(), ListenError> {
        todo!("bare-metal packet filter, board-specific")
    }

    fn recv(&mut self) -> Result<&[u8], ListenError> {
        todo!("bare-metal packet receive, board-specific")
    }
}

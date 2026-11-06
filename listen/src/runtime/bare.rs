//! Bare-metal runtime seam -- not yet implemented. Deferred until a concrete board is chosen
//! (ADR-0007): it will be an interrupt-driven async executor, not threads.

use crate::source::{ListenError, PacketSource};

pub fn run<S, H>(_src: S, _handler: H, _max_in_flight: usize) -> Result<(), ListenError>
where
    S: PacketSource,
    H: Fn(&[u8]) + Send + Sync + 'static,
{
    todo!("bare-metal runtime: async executor woken by the board's interrupts")
}

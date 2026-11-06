//! The platform layer: every OS- or board-specific service the other crates need, one backend per
//! compile target (ADR-0008, ADR-0009). The debug output sink behind `dbgprintln!`, the process
//! glue a binary needs once (`Alloc`, `abort`, `entry!`), and the locked nonce-ring store
//! (`with_locked_ring`). Unix also exposes `errno`.
#![no_std]

extern crate alloc;

#[cfg(not(any(unix, windows, target_os = "none")))]
compile_error!("common: no platform backend for this target yet");

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::{LibcAlloc as Alloc, StdoutWriter, abort, entry, errno, with_locked_ring};

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{StdoutWriter, WinAlloc as Alloc, abort, entry, with_locked_ring};

#[cfg(target_os = "none")]
mod none;
#[cfg(target_os = "none")]
pub use none::{BoardAlloc as Alloc, StdoutWriter, abort, entry, with_locked_ring};

/// A platform I/O failure. Payload-free: the typed OS error is logged where it happens (ADR-0003).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoError;

#[macro_export]
macro_rules! dbgprintln {
    ($($arg:tt)*) => {{
        #[cfg(debug_assertions)]
        {
            use core::fmt::Write as _;
            let _ = core::write!($crate::StdoutWriter, $($arg)*);
            let _ = $crate::StdoutWriter.write_str("\n");
        }
        // Release: emit nothing, but still reference the args so variables that exist only to be
        // logged don't trip `unused_variables`.
        #[cfg(not(debug_assertions))]
        let _ = core::format_args!($($arg)*);
    }};
}

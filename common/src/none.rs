//! Bare-metal (`target_os = "none"`) platform backend. Everything here is board-specific (output
//! over RTT/UART, a heap region, a flash- or RAM-backed nonce ring), so it waits until a board is
//! chosen. It type-checks but panics, and `entry!` refuses to compile.

use alloc::vec::Vec;

use crate::IoError;

pub struct StdoutWriter;

impl core::fmt::Write for StdoutWriter {
    fn write_str(&mut self, _s: &str) -> core::fmt::Result {
        todo!("bare-metal output sink (RTT/UART), board-specific")
    }
}

pub struct BoardAlloc;

// SAFETY: neither method ever returns, so no pointer that could break the `GlobalAlloc` contract is
// ever handed out.
unsafe impl core::alloc::GlobalAlloc for BoardAlloc {
    unsafe fn alloc(&self, _layout: core::alloc::Layout) -> *mut u8 {
        todo!("bare-metal allocator over a board heap region")
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: core::alloc::Layout) {
        todo!("bare-metal allocator over a board heap region")
    }
}

pub fn abort() -> ! {
    todo!("bare-metal abort (e.g. a UDF trap or reset)")
}

#[doc(hidden)]
#[macro_export]
macro_rules! __none_entry {
    ($app:path) => {
        compile_error!("common: no bare-metal entry point yet (needs a board's reset handler)");
    };
}
pub use crate::__none_entry as entry;

pub fn with_locked_ring<T, E: From<IoError>>(
    _f: impl FnOnce(&mut Vec<u8>) -> Result<T, E>,
) -> Result<T, E> {
    todo!("bare-metal nonce-ring store (flash or RAM), board-specific")
}

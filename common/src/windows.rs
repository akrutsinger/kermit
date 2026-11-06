//! Windows platform backend, via `windows-sys` directly (ADR-0002). Only the output sink is real so
//! far; the rest type-checks but panics, and `entry!` refuses to compile, so no binary can ship on
//! Windows until these are written.

use alloc::vec::Vec;

use windows_sys::Win32::Storage::FileSystem::WriteFile;
use windows_sys::Win32::System::Console::{GetStdHandle, STD_OUTPUT_HANDLE};

use crate::IoError;

/// `dbgprintln!`'s sink: unbuffered writes to the process's standard output handle.
pub struct StdoutWriter;

impl core::fmt::Write for StdoutWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let len = u32::try_from(s.len()).unwrap_or(u32::MAX);
        let mut written = 0u32;
        // SAFETY: `GetStdHandle` has no preconditions. `s.as_ptr()` is valid for reads of `len <=
        // s.len()` bytes for the whole call, `written` is a valid out-pointer, and a null
        // `OVERLAPPED` makes this a synchronous write. A missing or invalid handle just makes
        // `WriteFile` fail.
        unsafe {
            WriteFile(
                GetStdHandle(STD_OUTPUT_HANDLE),
                s.as_ptr(),
                len,
                &mut written,
                core::ptr::null_mut(),
            )
        };
        Ok(())
    }
}

/// `#[global_allocator]` backend. Not written yet (`HeapAlloc` only guarantees 16-byte alignment,
/// so larger alignments need over-allocation).
pub struct WinAlloc;

// SAFETY: neither method ever returns, so no pointer that could break the `GlobalAlloc` contract is
// ever handed out.
unsafe impl core::alloc::GlobalAlloc for WinAlloc {
    unsafe fn alloc(&self, _layout: core::alloc::Layout) -> *mut u8 {
        todo!("Windows allocator")
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: core::alloc::Layout) {
        todo!("Windows allocator")
    }
}

pub fn abort() -> ! {
    todo!("Windows abort (ExitProcess / __fastfail)")
}

#[doc(hidden)]
#[macro_export]
macro_rules! __windows_entry {
    ($app:path) => {
        compile_error!("common: no Windows entry point yet (no-CRT entry + GetCommandLineW)");
    };
}
pub use crate::__windows_entry as entry;

pub fn with_locked_ring<T, E: From<IoError>>(
    _f: impl FnOnce(&mut Vec<u8>) -> Result<T, E>,
) -> Result<T, E> {
    todo!("Windows nonce-ring store (CreateFileW + LockFileEx)")
}

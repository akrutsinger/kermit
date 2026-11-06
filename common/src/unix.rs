//! Unix (Linux, macOS, *BSD) platform backend, via libc and rustix.

use alloc::vec::Vec;

use rustix::fs::{FlockOperation, Mode, OFlags, SeekFrom, flock};

use crate::{IoError, dbgprintln};

#[cfg(target_os = "openbsd")]
use libc::__errno as errno_ptr;
#[cfg(any(target_os = "linux", target_os = "android"))]
use libc::__errno_location as errno_ptr;
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
use libc::__error as errno_ptr;

/// `dbgprintln!`'s sink: unbuffered writes to fd 1.
pub struct StdoutWriter;

impl core::fmt::Write for StdoutWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        // SAFETY: `s.as_ptr()` is valid for reads of `s.len()` bytes for the whole call, and `write`
        // only reads from it. fd 1 needs no validity guarantee: if stdout is closed or invalid,
        // `write` just fails with `EBADF`.
        unsafe { libc::write(1, s.as_ptr() as *const libc::c_void, s.len()) };
        Ok(())
    }
}

/// The calling thread's `errno`, read right after the libc call that failed.
pub fn errno() -> i32 {
    // SAFETY: the platform's `errno` accessor always returns a valid pointer to the calling thread's
    // `errno`.
    unsafe { *errno_ptr() }
}

/// `#[global_allocator]` backend: a pass-through to the C ABI `posix_memalign`/`free` (ADR-0005).
pub struct LibcAlloc;

// SAFETY: `alloc` returns either null (allocation failure) or a `posix_memalign` block of at least
// `layout.size()` bytes aligned to `layout.align()`, and `dealloc` returns that block to the
// matching `free`. Neither unwinds, since both are plain C calls. That is the `GlobalAlloc` contract.
unsafe impl core::alloc::GlobalAlloc for LibcAlloc {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        // `posix_memalign` needs a power of two that is also a multiple of the pointer size; both
        // `layout.align()` and the pointer size are powers of two, so their max is too.
        let align = layout.align().max(size_of::<*mut libc::c_void>());
        let mut ptr = core::ptr::null_mut();
        // SAFETY: `ptr` is a valid out-pointer and `align` meets `posix_memalign`'s requirements
        // (see above). On failure `ptr` is left untouched and null is returned, the failure signal
        // `GlobalAlloc` expects.
        if unsafe { libc::posix_memalign(&mut ptr, align, layout.size()) } != 0 {
            return core::ptr::null_mut();
        }
        ptr as *mut u8
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _: core::alloc::Layout) {
        // SAFETY: `dealloc`'s contract guarantees `ptr` came from this allocator's `alloc`, i.e.
        // from `posix_memalign`, so it is valid to hand to `free` exactly once.
        unsafe { libc::free(ptr as *mut libc::c_void) }
    }
}

/// Terminates the process immediately, without unwinding or running destructors.
pub fn abort() -> ! {
    // SAFETY: `abort` has no preconditions; it terminates the process and never returns.
    unsafe { libc::abort() }
}

/// Defines the process entry point and calls `$app(iface)` with the first CLI argument, if any.
/// On Unix that's the C runtime's `main(argc, argv)`; other targets supply their own entry symbol
/// and argument source behind the same `common::entry!` name.
#[doc(hidden)]
#[macro_export]
macro_rules! __unix_entry {
    ($app:path) => {
        #[unsafe(no_mangle)]
        extern "C" fn main(argc: i32, argv: *const *const u8) -> i32 {
            let iface: Option<&str> = if argc > 1 {
                // SAFETY: the C runtime passes `argc` valid entries in `argv`, each a NUL-terminated
                // string that lives for the whole process. `argc > 1` makes `argv.add(1)` in bounds,
                // and the string outlives any borrow handed to `$app`.
                unsafe {
                    core::ffi::CStr::from_ptr(*argv.add(1) as *const core::ffi::c_char)
                        .to_str()
                        .ok()
                }
            } else {
                None
            };
            $app(iface)
        }
    };
}
pub use crate::__unix_entry as entry;

/// Give `f` exclusive, locked access to the raw nonce-ring bytes: the current file contents (empty
/// the first time, before anything has been written) go in, and whatever `f` leaves in the buffer is
/// persisted back. Locking and persistence only -- `f` (e.g. `crypto::check_and_record_nonce`) owns
/// deciding whether those bytes are prior content, decrypting them, the replay check, and
/// re-encrypting.
///
/// The replay window is a read-modify-write on shared state with no serialization of its own. Under
/// the multi-threaded handler pool (and across concurrent processes) two callers could otherwise
/// both read the ring, both miss a nonce, and both record it, leaving a hole in the replay window.
/// Locking serializes the whole critical section, and the result is only persisted on `Ok` -- a
/// rejected replay (`Err`) leaves the stored ring untouched.
pub fn with_locked_ring<T, E: From<IoError>>(
    f: impl FnOnce(&mut Vec<u8>) -> Result<T, E>,
) -> Result<T, E> {
    // The typed errno is diagnostic-only (nothing branches on it), so it's logged here and erased to
    // the payload-free marker (ADR-0003).
    fn io_err(e: rustix::io::Errno) -> IoError {
        dbgprintln!("nonce io: {e:?}");
        IoError
    }

    let fd = rustix::fs::open(
        c"/tmp/nonce",
        OFlags::RDWR | OFlags::CREATE,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(io_err)?;

    // LOCK_EX serializes the whole critical section; the lock releases when `fd` is dropped at the
    // end of this function.
    flock(&fd, FlockOperation::LockExclusive).map_err(io_err)?;

    let mut ring = Vec::new();
    let mut chunk = [0u8; 64];
    loop {
        let read = rustix::io::read(&fd, &mut chunk).map_err(io_err)?;
        if read == 0 {
            break;
        }
        ring.extend_from_slice(&chunk[..read]);
    }

    let result = f(&mut ring)?;

    rustix::fs::seek(&fd, SeekFrom::Start(0)).map_err(io_err)?;
    rustix::io::write(&fd, &ring).map_err(io_err)?;
    Ok(result)
}

// Process-level glue the binary needs exactly once: the global allocator, the panic-path abort,
// and the entry point. Still libc-backed (ADR-0005); a syscall-only Linux build swaps these bodies,
// not their callers.

pub struct LibcAlloc;

// SAFETY: `alloc` returns either null (allocation failure) or a `memalign` block of at least
// `layout.size()` bytes aligned to `layout.align()`, and `dealloc` returns that block to the
// matching `free`. Neither unwinds, since both are plain C calls. That is the `GlobalAlloc` contract.
unsafe impl core::alloc::GlobalAlloc for LibcAlloc {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        // SAFETY: `Layout` guarantees `align` is a nonzero power of two, which is all `memalign`
        // requires; a null return is passed through as the failure signal `GlobalAlloc` expects.
        unsafe { libc::memalign(layout.align(), layout.size()) as *mut u8 }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _: core::alloc::Layout) {
        // SAFETY: `dealloc`'s contract guarantees `ptr` came from this allocator's `alloc`, i.e.
        // from `memalign`, so it is valid to hand to `free` exactly once.
        unsafe { libc::free(ptr as *mut libc::c_void) }
    }
}

pub fn abort() -> ! {
    // SAFETY: `abort` has no preconditions; it terminates the process and never returns.
    unsafe { libc::abort() }
}

/// Defines the process entry point and calls `$app(iface)` with the first CLI argument, if any.
/// On Linux that's the C runtime's `main(argc, argv)`; other OSes supply their own entry symbol
/// and argument source behind the same `os::entry!` name.
#[doc(hidden)]
#[macro_export]
macro_rules! __linux_entry {
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
pub use crate::__linux_entry as entry;

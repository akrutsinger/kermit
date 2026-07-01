#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]

extern crate alloc;

mod filter;
mod os;
mod runtime;
mod source;

#[cfg(not(test))]
use common::dbgprintln;
#[cfg(not(test))]
use crypto::{APP_NONCE_LEN, check_and_record_nonce};
#[cfg(not(test))]
use getrandom::fill;
#[cfg(not(test))]
use source::PacketSource as _;

// The embassy runtime is preserved as a seam (see runtime/embassy.rs) but is
// not yet wired into `main`; fail loudly rather than with a confusing error.
#[cfg(all(not(test), feature = "runtime-embassy"))]
compile_error!(
    "listen: runtime-embassy is a future seam, not yet wired into main; build with runtime-threads"
);

/// Worker threads draining the capture queue. Handlers run in parallel across
/// these; shared state they touch (the replay-nonce file) is serialized inside
/// `check_and_record_nonce` via `flock`.
#[cfg(all(not(test), feature = "runtime-threads"))]
const WORKERS: usize = 4;

#[cfg(not(test))]
struct LibcAlloc;

#[cfg(not(test))]
unsafe impl core::alloc::GlobalAlloc for LibcAlloc {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        unsafe { libc::memalign(layout.align(), layout.size()) as *mut u8 }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _: core::alloc::Layout) {
        unsafe { libc::free(ptr as *mut libc::c_void) }
    }
}

#[cfg(not(test))]
#[global_allocator]
static ALLOCATOR: LibcAlloc = LibcAlloc;

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    dbgprintln!("panic: {info}");
    unsafe { libc::abort() }
}

// The precompiled liballoc rlib is built with panic=unwind and references this symbol.
// Provide a stub so the linker is satisfied; it is never called because panic=abort.
#[cfg(not(test))]
#[unsafe(no_mangle)]
extern "C" fn rust_eh_personality() {}

/// Per-packet handler, run on a worker thread. The burn loop stands in for real
/// processing so concurrent capture is observable while testing.
#[cfg(all(not(test), feature = "runtime-threads"))]
fn handle_packet(pkt: &[u8]) {
    dbgprintln!("matched: {} bytes", pkt.len());

    let base_key = *b"listen-test-key-0000000000000000";
    let mut nonce = [0u8; APP_NONCE_LEN];
    if let Err(e) = fill(&mut nonce) {
        dbgprintln!("failed to generate nonce: {e}");
        return;
    }
    if let Err(e) = check_and_record_nonce(&nonce, &base_key) {
        dbgprintln!("nonce check failed: {e}");
        return;
    }

    for _ in 0..400000000 {
        // burn
    }

    dbgprintln!("done processing packet");
}

#[cfg(all(not(test), feature = "runtime-threads"))]
#[unsafe(no_mangle)]
extern "C" fn main(argc: i32, argv: *const *const u8) -> i32 {
    let iface: Option<&str> = if argc > 1 {
        unsafe {
            core::ffi::CStr::from_ptr(*argv.add(1) as *const core::ffi::c_char)
                .to_str()
                .ok()
        }
    } else {
        None
    };

    let mut src = match os::Source::open(iface) {
        Ok(src) => src,
        Err(e) => {
            dbgprintln!("failed to open packet source: {e}");
            return 1;
        }
    };

    if let Err(e) = src.attach_filter(&os::FILTER) {
        dbgprintln!("failed to attach filter: {e}");
        return 1;
    }

    match runtime::run(src, handle_packet, WORKERS) {
        Ok(()) => 0,
        Err(e) => {
            dbgprintln!("capture stopped: {e}");
            1
        }
    }
}

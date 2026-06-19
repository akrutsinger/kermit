#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]

mod filter;
mod os;
mod source;

use common::dbgprintln;
use crypto::{APP_NONCE_LEN, check_and_record_nonce};
use getrandom::fill;
use source::PacketSource;

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
    #[cfg(debug_assertions)]
    {
        use core::fmt::Write as _;
        let _ = core::write!(common::StdoutWriter, "panic: {info}\n");
    }
    unsafe { libc::abort() }
}

// The precompiled liballoc rlib is built with panic=unwind and references this symbol.
// Provide a stub so the linker is satisfied; it is never called because panic=abort.
#[cfg(not(test))]
#[unsafe(no_mangle)]
extern "C" fn rust_eh_personality() {}

#[cfg(not(test))]
fn packet_handler(pkt: &[u8]) {
    dbgprintln!("matched: {} bytes", pkt.len());
}

#[cfg(not(test))]
#[unsafe(no_mangle)]
extern "C" fn main(argc: i32, argv: *const *const u8) -> i32 {
    let base_key = *b"listen-test-key-0000000000000000";
    let mut nonce = [0u8; APP_NONCE_LEN];
    if let Err(e) = fill(&mut nonce) {
        dbgprintln!("failed to generate nonce: {e}");
        return 1;
    }
    match check_and_record_nonce(&nonce, &base_key) {
        Ok(()) => (),
        Err(e) => {
            dbgprintln!("nonce check failed: {e}");
            return 1;
        }
    }

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

    match src.attach_filter(&os::FILTER) {
        Ok(()) => (),
        Err(e) => {
            dbgprintln!("failed to attach filter: {e}");
            return 1;
        }
    }

    loop {
        match src.recv() {
            Ok(pkt) => packet_handler(pkt),
            Err(e) => {
                dbgprintln!("capture stopped: {e}");
                break;
            }
        }
    }

    0
}

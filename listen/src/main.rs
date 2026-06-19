#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]

mod executor;
mod filter;
mod os;
mod source;

use common::dbgprintln;
use crypto::{APP_NONCE_LEN, check_and_record_nonce};
use getrandom::fill;
#[cfg(not(test))]
use source::PacketSource as _;

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
        let _ = core::writeln!(common::StdoutWriter, "panic: {info}");
    }
    unsafe { libc::abort() }
}

// The precompiled liballoc rlib is built with panic=unwind and references this symbol.
// Provide a stub so the linker is satisfied; it is never called because panic=abort.
#[cfg(not(test))]
#[unsafe(no_mangle)]
extern "C" fn rust_eh_personality() {}

// Single-threaded critical section: no interrupts to manage in Linux userspace.
#[cfg(not(test))]
struct LinuxCritSec;
#[cfg(not(test))]
critical_section::set_impl!(LinuxCritSec);
#[cfg(not(test))]
unsafe impl critical_section::Impl for LinuxCritSec {
    unsafe fn acquire() -> critical_section::RawRestoreState {}
    unsafe fn release(_: critical_section::RawRestoreState) {}
}

#[cfg(not(test))]
#[embassy_executor::task(pool_size = 4)]
async fn packet_handler(_buf: [u8; 2048], len: usize) {
    dbgprintln!("matched: {} bytes", len);

    let base_key = *b"listen-test-key-0000000000000000";
    let mut nonce = [0u8; APP_NONCE_LEN];
    if let Err(e) = fill(&mut nonce) {
        dbgprintln!("failed to generate nonce: {e}");
        return;
    }
    match check_and_record_nonce(&nonce, &base_key) {
        Ok(()) => (),
        Err(e) => {
            dbgprintln!("nonce check failed: {e}");
        }
    }
}

#[cfg(not(test))]
#[embassy_executor::task]
async fn recv_loop(mut src: os::Source, spawner: embassy_executor::Spawner) {
    use core::future::poll_fn;
    use core::task::Poll;

    loop {
        match src.try_recv() {
            Ok(Some(pkt)) => {
                let mut buf = [0u8; 2048];
                let len = pkt.len().min(2048);
                buf[..len].copy_from_slice(&pkt[..len]);
                if spawner.spawn(packet_handler(buf, len)).is_err() {
                    dbgprintln!("packet pool exhausted, dropping packet");
                }
            }
            Ok(None) => {
                poll_fn(|cx| {
                    if executor::SOCKET_READY.swap(false, core::sync::atomic::Ordering::AcqRel) {
                        Poll::Ready(())
                    } else {
                        executor::SOCKET_WAKER.store(cx.waker());
                        Poll::Pending
                    }
                })
                .await;
            }
            Err(e) => {
                dbgprintln!("capture stopped: {e}");
                break;
            }
        }
    }
}

#[cfg(not(test))]
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

    match src.attach_filter(&os::FILTER) {
        Ok(()) => (),
        Err(e) => {
            dbgprintln!("failed to attach filter: {e}");
            return 1;
        }
    }

    use rustix::fd::AsRawFd as _;
    let socket_fd = src.as_raw_fd();

    static EXECUTOR: static_cell::StaticCell<executor::Executor> = static_cell::StaticCell::new();
    let executor = EXECUTOR.init(executor::Executor::new(socket_fd));
    executor.run(|spawner| {
        spawner.spawn(recv_loop(src, spawner)).unwrap();
    })
}

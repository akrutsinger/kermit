#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]

// Everything below only exists in the real no_std/no_main binary: `cfg(test)` builds run under
// std's own test harness, which supplies its own `main` and needs `std`, not this allocator/panic
// handler/entry point.
#[cfg(not(test))]
mod entry {
    use common::{dbgprintln, with_locked_ring};
    use crypto::NONCE_WINDOW;
    use crypto::check_and_record_nonce;
    use getrandom::fill;

    use listen::os;
    use listen::runtime;
    use listen::source::PacketSource as _;

    #[global_allocator]
    static ALLOCATOR: common::Alloc = common::Alloc;

    #[panic_handler]
    fn panic(info: &core::panic::PanicInfo) -> ! {
        dbgprintln!("panic: {info}");
        common::abort()
    }

    // The precompiled liballoc rlib is built with panic=unwind and references this symbol. Provide a
    // stub so the linker is satisfied; it is never called because panic=abort.
    #[unsafe(no_mangle)]
    extern "C" fn rust_eh_personality() {}

    /// Per-packet handler, run on its own spawned thread. The burn loop stands in for real processing
    /// so concurrent capture is observable while testing.
    #[cfg(feature = "runtime-threads")]
    fn handle_packet(pkt: &[u8]) {
        dbgprintln!("matched: {} bytes", pkt.len());

        let base_key = *b"listen-test-key-0000000000000000";
        // Replay-nonce width for this demo; matches the default `StreamAead` NONCE_LEN parameter.
        const REPLAY_NONCE_LEN: usize = 8;
        let mut nonce = [0u8; REPLAY_NONCE_LEN];
        if let Err(e) = fill(&mut nonce) {
            dbgprintln!("failed to generate nonce: {e}");
            return;
        }
        if let Err(e) = with_locked_ring(|ring| check_and_record_nonce(ring, &nonce, &base_key)) {
            dbgprintln!("nonce check failed: {e}");
            return;
        }

        for _ in 0..400000000 {
            // burn
        }

        dbgprintln!("done processing packet");
    }

    #[cfg(feature = "runtime-threads")]
    common::entry!(app_main);

    /// OS-agnostic program body; the per-target `common::entry!` shim hands it the first CLI
    /// argument.
    #[cfg(feature = "runtime-threads")]
    fn app_main(iface: Option<&str>) -> i32 {
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

        // Cap concurrent handlers at the replay-nonce window: no point admitting more in-flight packets
        // than the number of nonces `check_and_record_nonce` remembers.
        match runtime::run(src, handle_packet, NONCE_WINDOW) {
            Ok(()) => 0,
            Err(e) => {
                dbgprintln!("capture stopped: {e}");
                1
            }
        }
    }
}

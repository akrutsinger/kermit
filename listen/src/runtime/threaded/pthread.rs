//! POSIX pthread backend: thread-per-packet. The recv loop (the calling thread) blocks on the
//! socket; each packet that arrives spawns one detached handler thread and the loop immediately
//! goes back to blocking recv. A POSIX counting `Semaphore`, initialized with `max_in_flight`
//! permits, caps how many handler threads may be in flight at once -- a packet arriving with no
//! permit available is dropped rather than queued or left to block recv.

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::cell::UnsafeCell;
use core::ffi::c_void;

use common::{dbgprintln, errno};

use crate::source::{ListenError, PacketSource};

const FRAME_LEN: usize = 2048;

#[derive(Clone, Copy)]
struct Frame {
    buf: [u8; FRAME_LEN],
    len: usize,
}

impl Frame {
    const EMPTY: Frame = Frame {
        buf: [0u8; FRAME_LEN],
        len: 0,
    };
}

/// Drive the capture loop to completion, spawning at most `max_in_flight` (clamped to >= 1)
/// concurrent handler threads, one per packet. Returns when `src.recv` reports a fatal error; for a
/// real socket that is effectively never, so this parks the calling thread for the program's life.
/// Also errors up front if the OS can't create a semaphore with `max_in_flight` permits.
pub fn run<S, H>(mut src: S, handler: H, max_in_flight: usize) -> Result<(), ListenError>
where
    S: PacketSource,
    H: Fn(&[u8]) + Send + Sync + 'static,
{
    // `S::MAX_FRAME` is only the size a *source* declares at compile time; a backend whose real max
    // is discovered at runtime (e.g. BSD's `BIOCGBLEN`) can't be checked here -- see the truncation
    // log below for that case.
    const {
        assert!(
            S::MAX_FRAME <= FRAME_LEN,
            "PacketSource::MAX_FRAME exceeds the runtime's fixed FRAME_LEN"
        )
    };

    let cap = max_in_flight.max(1);
    let sem = Semaphore::new(cap)?;
    let handler = Arc::new(handler);

    let result = loop {
        match src.recv() {
            Ok(pkt) => {
                if !sem.try_acquire() {
                    dbgprintln!("listen: max_in_flight reached, dropping packet");
                } else {
                    if pkt.len() > FRAME_LEN {
                        dbgprintln!(
                            "listen: packet len {} exceeds FRAME_LEN {}, truncating",
                            pkt.len(),
                            FRAME_LEN
                        );
                    }
                    let len = pkt.len().min(FRAME_LEN);
                    let mut frame = Frame::EMPTY;
                    frame.buf[..len].copy_from_slice(&pkt[..len]);
                    frame.len = len;

                    let h = handler.clone();
                    let s = sem.clone();
                    if let Err(e) = spawn_detached(move || {
                        h(&frame.buf[..frame.len]);
                        s.release();
                    }) {
                        // The closure above never ran, so its `s.release()` never fires -- release
                        // the permit here instead.
                        sem.release();
                        dbgprintln!("listen: failed to spawn handler: {e}");
                    }
                }
            }
            Err(e) => break Err(e),
        }
    };

    // Every spawned handler releases its permit on exit; reacquiring all `cap` of them blocks until
    // the last straggler has finished, so shutdown doesn't race running handlers.
    for _ in 0..cap {
        sem.acquire()?;
    }
    result
}

/// Thin wrapper around a POSIX counting semaphore (`sem_init`/`sem_wait`/`sem_trywait`/
/// `sem_post`), used here to cap in-flight handler threads: `new(cap)` starts with `cap` permits,
/// `try_acquire` takes one without blocking (fails if none are left), `release` returns one, and
/// `acquire` blocks until one is available.
///
/// Only ever lives inside the `Arc` that `new` initializes it in, and is never moved out: POSIX
/// leaves using a *copy* of a `sem_t` undefined, so the semaphore must stay where `sem_init` put it.
#[repr(transparent)]
struct Semaphore(UnsafeCell<libc::sem_t>);

// SAFETY: a process-private (`pshared = 0`) `sem_t` has no thread affinity: any thread of this
// process may post, wait on, or destroy it, so ownership can move between threads.
unsafe impl Send for Semaphore {}
// SAFETY: POSIX specifies `sem_wait`/`sem_trywait`/`sem_post` as safe to call concurrently on the
// same semaphore, and those are the only operations `&Semaphore` exposes.
unsafe impl Sync for Semaphore {}

impl Semaphore {
    /// Create a semaphore holding `permits` permits, initialized in place in its final `Arc`.
    /// Errors if `permits` exceeds what the OS allows (`SEM_VALUE_MAX`) or the OS has no unnamed
    /// semaphores (macOS).
    #[cfg_attr(
        target_os = "macos",
        expect(
            deprecated,
            reason = "macOS has no unnamed POSIX semaphores, so `sem_init` fails at runtime there \
                      until the per-OS runtime split gives macOS its own semaphore"
        )
    )]
    fn new(permits: usize) -> Result<Arc<Self>, ListenError> {
        let Ok(permits) = libc::c_uint::try_from(permits) else {
            dbgprintln!("semaphore permits {permits} exceed c_uint");
            return Err(ListenError::Io);
        };

        let mut sem = Arc::<Self>::new_uninit();
        let Some(slot) = Arc::get_mut(&mut sem) else {
            unreachable!("a freshly allocated Arc has no other references");
        };
        // `#[repr(transparent)]` over `UnsafeCell<sem_t>`, which itself has the layout of `sem_t`.
        let raw = slot.as_mut_ptr().cast::<libc::sem_t>();

        // pshared = 0: shared between threads of this process, not across processes.
        // SAFETY: `raw` points to writable, properly aligned storage for a `sem_t` inside the `Arc`
        // allocation the semaphore will live in for good, which `sem_init` initializes in place.
        if unsafe { libc::sem_init(raw, 0, permits) } != 0 {
            dbgprintln!("sem_init failed: errno {}", errno());
            return Err(ListenError::Io);
        }
        // SAFETY: `sem_init` succeeded, so the `sem_t` -- the `Semaphore`'s only field -- is
        // initialized.
        Ok(unsafe { sem.assume_init() })
    }

    /// Take a permit without blocking. Returns false if none are available.
    fn try_acquire(&self) -> bool {
        // SAFETY: `self.0` holds the semaphore initialized in `new`, and it stays initialized until
        // `Drop`, which can't run while `&self` is borrowed.
        unsafe { libc::sem_trywait(self.0.get()) == 0 }
    }

    /// Block until a permit is available, then take it. Retries on `EINTR`; any other failure
    /// means the semaphore is unusable and is returned instead of retried forever.
    fn acquire(&self) -> Result<(), ListenError> {
        loop {
            // SAFETY: as in `try_acquire`, `self.0` is an initialized, not-yet-destroyed semaphore.
            if unsafe { libc::sem_wait(self.0.get()) } == 0 {
                return Ok(());
            }
            let e = errno();
            if e != libc::EINTR {
                dbgprintln!("sem_wait failed: errno {e}");
                return Err(ListenError::Io);
            }
        }
    }

    /// Return a permit taken by `try_acquire` or `acquire`.
    /// Failure (`EOVERFLOW` from releasing more than was taken, or `EINVAL`) is a bug with no
    /// recovery at the call sites, so it is logged rather than returned.
    fn release(&self) {
        // SAFETY: as in `try_acquire`, `self.0` is an initialized, not-yet-destroyed semaphore.
        if unsafe { libc::sem_post(self.0.get()) } != 0 {
            dbgprintln!("sem_post failed: errno {}", errno());
        }
    }
}

impl Drop for Semaphore {
    #[cfg_attr(
        target_os = "macos",
        expect(deprecated, reason = "see `Semaphore::new`")
    )]
    fn drop(&mut self) {
        // SAFETY: `&mut self` means no other reference exists, so no thread can be blocked in
        // `sem_wait` on it (POSIX requires that for `sem_destroy`), and `Drop` runs exactly once.
        unsafe { libc::sem_destroy(self.0.get()) };
    }
}

/// Spawn a detached pthread running `f`. The thread reclaims its own OS resources on exit; there is
/// no handle to join because `run` tracks completion through `Semaphore`, not thread identity.
fn spawn_detached<F: FnOnce() + Send + 'static>(f: F) -> Result<(), ListenError> {
    extern "C" fn trampoline(arg: *mut c_void) -> *mut c_void {
        // SAFETY: `arg` is the pointer `spawn_detached` made with `Box::into_raw` on a
        // `Box<Box<dyn FnOnce() + Send>>`, and `pthread_create` passes it to exactly one trampoline
        // call, so ownership is reclaimed exactly once and with the original type.
        let f: Box<Box<dyn FnOnce() + Send>> = unsafe { Box::from_raw(arg as *mut _) };
        f();
        core::ptr::null_mut()
    }

    // Double box: a thin pointer for the C ABI around the fat `dyn` pointer.
    let boxed: Box<Box<dyn FnOnce() + Send>> = Box::new(Box::new(f));
    let arg = Box::into_raw(boxed) as *mut c_void;

    let mut handle: libc::pthread_t = 0;
    // SAFETY: `handle` is a valid out-pointer, a null attr selects defaults, `trampoline` has the
    // `extern "C" fn(*mut c_void) -> *mut c_void` signature pthreads expects, and `arg` stays valid
    // (leaked, `'static + Send`) until the new thread takes ownership of it.
    let rc = unsafe { libc::pthread_create(&mut handle, core::ptr::null(), trampoline, arg) };
    if rc != 0 {
        // Thread never started; reclaim the closure we leaked into `arg`.
        // SAFETY: on failure no thread received `arg`, so we still own the `Box::into_raw`
        // allocation and free it exactly once, with the type it was created as.
        unsafe { drop(Box::from_raw(arg as *mut Box<dyn FnOnce() + Send>)) };
        dbgprintln!("pthread_create failed: {rc}");
        return Err(ListenError::Io);
    }
    // SAFETY: `handle` was filled in by the successful `pthread_create` above and hasn't been joined
    // or detached; detaching a thread that has already exited is valid and frees it immediately.
    unsafe { libc::pthread_detach(handle) };
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Condvar, Mutex};
    use std::time::Duration;

    // Yields `count` empty frames, then signals end-of-stream so `run` returns.
    struct FakeSource {
        remaining: usize,
        frame: [u8; 4],
    }

    impl PacketSource for FakeSource {
        type Filter = ();
        const MAX_FRAME: usize = 4;

        fn open(_iface: Option<&str>) -> Result<Self, ListenError> {
            unreachable!("tests construct FakeSource directly")
        }

        fn attach_filter(&mut self, _prog: &()) -> Result<(), ListenError> {
            Ok(())
        }

        fn recv(&mut self) -> Result<&[u8], ListenError> {
            if self.remaining == 0 {
                return Err(ListenError::NoIface); // sentinel: stop the recv loop
            }
            self.remaining -= 1;
            Ok(&self.frame)
        }
    }

    #[test]
    fn try_acquire_respects_cap() {
        let sem = Semaphore::new(1).unwrap();
        assert!(sem.try_acquire());
        assert!(
            !sem.try_acquire(),
            "cap is 1, a second permit must not be available"
        );
        sem.release();
        assert!(
            sem.try_acquire(),
            "permit returned by release() should be reusable"
        );
    }

    #[test]
    fn acquire_blocks_until_a_permit_is_released() {
        let sem = Semaphore::new(2).unwrap();
        assert!(sem.try_acquire());
        assert!(sem.try_acquire());

        let s = sem.clone();
        let releaser = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            s.release();
            s.release();
        });

        // Returns only once both permits above have been released.
        sem.acquire().unwrap();
        sem.acquire().unwrap();
        releaser.join().unwrap();
    }

    // `c_uint::MAX` fits the type but is above every POSIX `SEM_VALUE_MAX` (glibc/musl: `INT_MAX`),
    // so `sem_init` fails with `EINVAL`; `new` must report that instead of using the uninitialized
    // semaphore.
    #[test]
    fn new_errors_when_permits_exceed_sem_value_max() {
        let result = Semaphore::new(libc::c_uint::MAX as usize);

        assert!(
            result.is_err(),
            "sem_init should reject c_uint::MAX permits"
        );
    }

    #[derive(Default)]
    struct RunGate {
        arrived: usize,   // monotonic: gates the rendezvous
        in_flight: usize, // inc on entry, dec on exit: measures simultaneity
        max_in_flight: usize,
    }

    // The recv loop must be able to feed a new packet and spawn a new handler while a previous
    // handler is still running. Each handler bumps `in_flight`, then rendezvous on the monotonic
    // `arrived` count: with a cap of two, both are still in flight when released, so
    // `max_in_flight` reaches 2. A serial (cap-1) run would strand the second handler behind the
    // first, so the high-water mark would stay at 1.
    #[test]
    fn handlers_run_concurrently_up_to_the_cap() {
        let gate = Arc::new((Mutex::new(RunGate::default()), Condvar::new()));

        let g = gate.clone();
        let handler = move |_pkt: &[u8]| {
            let (lock, cvar) = &*g;
            let mut s = lock.lock().unwrap();
            s.arrived += 1;
            s.in_flight += 1;
            if s.arrived >= 2 {
                cvar.notify_all();
            } else {
                // Park until a partner arrives, bounded so a non-concurrent run fails fast instead
                // of hanging the test.
                s = cvar
                    .wait_timeout_while(s, Duration::from_secs(2), |s| s.arrived < 2)
                    .unwrap()
                    .0;
            }
            s.max_in_flight = s.max_in_flight.max(s.in_flight);
            s.in_flight -= 1;
        };

        // Exactly one packet per cap slot: each spawned handler parks at the rendezvous, with no
        // third packet to be dropped or stranded.
        let src = FakeSource {
            remaining: 2,
            frame: [0u8; 4],
        };

        // Returns once the source is drained and all spawned handlers have finished.
        let _ = run(src, handler, 2);

        let max = gate.0.lock().unwrap().max_in_flight;
        assert!(
            max >= 2,
            "expected >=2 handlers in flight at once, saw {max}"
        );
    }

    #[test]
    fn packet_beyond_cap_is_dropped() {
        let hits = Arc::new(Mutex::new(0usize));
        let release = Arc::new((Mutex::new(false), Condvar::new()));

        let h = hits.clone();
        let r = release.clone();
        let handler = move |_pkt: &[u8]| {
            *h.lock().unwrap() += 1;
            // Hold the only slot open until the test allows it to finish, so the second packet is
            // guaranteed to see the cap already full rather than racing a fast handler.
            let (lock, cvar) = &*r;
            let mut done = lock.lock().unwrap();
            done = cvar
                .wait_timeout_while(done, Duration::from_secs(2), |d| !*d)
                .unwrap()
                .0;
            drop(done);
        };

        // Two packets, cap of 1: recv() for the second one happens on the calling thread while the
        // first handler thread is still parked above, so it must see the cap full.
        let src = FakeSource {
            remaining: 2,
            frame: [0u8; 4],
        };

        let runner = std::thread::spawn(move || run(src, handler, 1));

        // Give the first handler time to reserve its slot and reach the park point before releasing
        // it.
        std::thread::sleep(Duration::from_millis(100));
        {
            let (lock, cvar) = &*release;
            *lock.lock().unwrap() = true;
            cvar.notify_all();
        }
        let _ = runner.join().unwrap();

        assert_eq!(
            *hits.lock().unwrap(),
            1,
            "only the first packet should have been handled"
        );
    }
}

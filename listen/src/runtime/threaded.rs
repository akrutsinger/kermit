//! Thread-pool runtime for hosted OSes. A dedicated recv loop (the calling
//! thread) blocks on the socket and pushes frames into a bounded queue; a pool
//! of `workers` pthreads drains the queue and runs the handler. This gives true
//! parallelism (a CPU-bound handler no longer stalls packet capture) and
//! decouples the two stages so a slow handler just backs up the bounded queue
//! (oldest-wins: a full queue drops the new frame) instead of blocking recv.
//!
//! Threads here are POSIX pthreads via `libc`; a Windows `runtime-threads`
//! build would supply its own spawn/queue primitives behind the same `run`.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::ffi::c_void;

use common::dbgprintln;
use rustix::io::Errno;

use crate::source::{ListenError, PacketSource};

/// Bounded queue depth. At ~2 KiB per slot this is the backpressure window
/// between the recv loop and the worker pool before frames start dropping.
const QUEUE_DEPTH: usize = 256;
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

/// Drive the capture loop to completion. Spawns `workers` (clamped to >= 1)
/// handler threads, then runs the blocking recv loop on the calling thread.
/// Returns when `src.recv` reports a fatal error; for a real socket that is
/// effectively never, so this parks the main thread for the program's life.
pub fn run<S, H>(mut src: S, handler: H, workers: usize) -> Result<(), ListenError>
where
    S: PacketSource,
    H: Fn(&[u8]) + Send + Sync + 'static,
{
    let queue = Arc::new(Queue::new());
    let handler = Arc::new(handler);

    let mut pool: Vec<Thread> = Vec::with_capacity(workers.max(1));
    for _ in 0..workers.max(1) {
        let q = queue.clone();
        let h = handler.clone();
        match spawn(move || {
            while let Some(frame) = q.pop() {
                (*h)(&frame.buf[..frame.len]);
            }
        }) {
            Ok(t) => pool.push(t),
            Err(e) => {
                // Bring down whatever started before propagating.
                queue.close();
                for t in pool {
                    t.join();
                }
                return Err(e);
            }
        }
    }

    let result = loop {
        match src.recv() {
            Ok(pkt) => {
                let len = pkt.len().min(FRAME_LEN);
                let mut frame = Frame::EMPTY;
                frame.buf[..len].copy_from_slice(&pkt[..len]);
                frame.len = len;
                if !queue.push(frame) {
                    dbgprintln!("listen: queue full, dropping packet");
                }
            }
            Err(e) => break Err(e),
        }
    };

    queue.close();
    for t in pool {
        t.join();
    }
    result
}

// Bounded blocking queue: pthread mutex + condvar around a fixed ring.

struct Ring {
    slots: Vec<Frame>,
    head: usize,
    len: usize,
    closed: bool,
}

struct Queue {
    mutex: UnsafeCell<libc::pthread_mutex_t>,
    not_empty: UnsafeCell<libc::pthread_cond_t>,
    ring: UnsafeCell<Ring>,
}

// All access to `ring` is serialized by `mutex`; the pthread primitives are
// themselves the synchronization point.
unsafe impl Send for Queue {}
unsafe impl Sync for Queue {}

impl Queue {
    fn new() -> Self {
        let mut slots = Vec::with_capacity(QUEUE_DEPTH);
        slots.resize(QUEUE_DEPTH, Frame::EMPTY);
        Queue {
            mutex: UnsafeCell::new(libc::PTHREAD_MUTEX_INITIALIZER),
            not_empty: UnsafeCell::new(libc::PTHREAD_COND_INITIALIZER),
            ring: UnsafeCell::new(Ring {
                slots,
                head: 0,
                len: 0,
                closed: false,
            }),
        }
    }

    /// Enqueue a frame. Returns false if the queue is full or closed (the frame
    /// is dropped); callers treat a full queue as backpressure.
    fn push(&self, frame: Frame) -> bool {
        unsafe {
            libc::pthread_mutex_lock(self.mutex.get());
            let ring = &mut *self.ring.get();
            let cap = ring.slots.len();
            if ring.closed || ring.len == cap {
                libc::pthread_mutex_unlock(self.mutex.get());
                return false;
            }
            let idx = (ring.head + ring.len) % cap;
            ring.slots[idx] = frame;
            ring.len += 1;
            libc::pthread_cond_signal(self.not_empty.get());
            libc::pthread_mutex_unlock(self.mutex.get());
            true
        }
    }

    /// Block until a frame is available, or return None once the queue is
    /// closed and drained (the signal for a worker to exit).
    fn pop(&self) -> Option<Frame> {
        unsafe {
            libc::pthread_mutex_lock(self.mutex.get());
            loop {
                let ring = &mut *self.ring.get();
                if ring.len > 0 {
                    let cap = ring.slots.len();
                    let frame = ring.slots[ring.head];
                    ring.head = (ring.head + 1) % cap;
                    ring.len -= 1;
                    libc::pthread_mutex_unlock(self.mutex.get());
                    return Some(frame);
                }
                if ring.closed {
                    libc::pthread_mutex_unlock(self.mutex.get());
                    return None;
                }
                // Releases the mutex while parked, reacquires it on wake.
                libc::pthread_cond_wait(self.not_empty.get(), self.mutex.get());
            }
        }
    }

    /// Mark the queue closed and wake every worker so they can drain and exit.
    fn close(&self) {
        unsafe {
            libc::pthread_mutex_lock(self.mutex.get());
            (*self.ring.get()).closed = true;
            libc::pthread_cond_broadcast(self.not_empty.get());
            libc::pthread_mutex_unlock(self.mutex.get());
        }
    }
}

impl Drop for Queue {
    fn drop(&mut self) {
        unsafe {
            libc::pthread_cond_destroy(self.not_empty.get());
            libc::pthread_mutex_destroy(self.mutex.get());
        }
    }
}

// Minimal pthread spawn/join wrapper.

struct Thread {
    handle: libc::pthread_t,
}

impl Thread {
    fn join(self) {
        unsafe { libc::pthread_join(self.handle, core::ptr::null_mut()) };
    }
}

fn spawn<F: FnOnce() + Send + 'static>(f: F) -> Result<Thread, ListenError> {
    extern "C" fn trampoline(arg: *mut c_void) -> *mut c_void {
        let f: Box<Box<dyn FnOnce() + Send>> = unsafe { Box::from_raw(arg as *mut _) };
        f();
        core::ptr::null_mut()
    }

    // Double box: a thin pointer for the C ABI around the fat `dyn` pointer.
    let boxed: Box<Box<dyn FnOnce() + Send>> = Box::new(Box::new(f));
    let arg = Box::into_raw(boxed) as *mut c_void;

    let mut handle: libc::pthread_t = 0;
    let rc = unsafe {
        libc::pthread_create(&mut handle, core::ptr::null(), trampoline, arg)
    };
    if rc != 0 {
        // Thread never started; reclaim the closure we leaked into `arg`.
        unsafe { drop(Box::from_raw(arg as *mut Box<dyn FnOnce() + Send>)) };
        return Err(ListenError::Io(Errno::from_raw_os_error(rc)));
    }
    Ok(Thread { handle })
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

    #[derive(Default)]
    struct Gate {
        arrived: usize,   // monotonic: gates the rendezvous
        in_flight: usize, // inc on entry, dec on exit: measures simultaneity
        max_in_flight: usize,
    }

    // The recv loop must be able to feed a new packet and start a new handler
    // while a previous handler is still running. Each handler bumps `in_flight`,
    // then rendezvous on the monotonic `arrived` count: with two workers both
    // are still in flight when released, so `max_in_flight` reaches 2. A serial
    // pool runs them back to back: the first leaves (in_flight back to 0)
    // before the second arrives, so the high-water mark stays at 1.
    #[test]
    fn handlers_run_concurrently() {
        let gate = Arc::new((Mutex::new(Gate::default()), Condvar::new()));

        let g = gate.clone();
        let handler = move |_pkt: &[u8]| {
            let (lock, cvar) = &*g;
            let mut s = lock.lock().unwrap();
            s.arrived += 1;
            s.in_flight += 1;
            if s.arrived >= 2 {
                cvar.notify_all();
            } else {
                // Park until a partner arrives, bounded so a serial pool fails
                // fast instead of hanging the test.
                s = cvar
                    .wait_timeout_while(s, Duration::from_secs(2), |s| s.arrived < 2)
                    .unwrap()
                    .0;
            }
            s.max_in_flight = s.max_in_flight.max(s.in_flight);
            s.in_flight -= 1;
        };

        // Exactly one frame per worker: each worker handles one and parks at the
        // rendezvous, with no second wave to strand a handler.
        let src = FakeSource {
            remaining: 2,
            frame: [0u8; 4],
        };

        // Returns once the source is drained and both workers have joined.
        let _ = run(src, handler, 2);

        let max = gate.0.lock().unwrap().max_in_flight;
        assert!(max >= 2, "expected >=2 handlers in flight at once, saw {max}");
    }
}

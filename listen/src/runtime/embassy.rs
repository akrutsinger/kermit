//! Embassy async runtime -- the embedded seam, NOT built by default.
//!
//! This is the single-threaded cooperative path: an `embassy_executor` raw
//! executor driven by a platform `Reactor` that sleeps the core until a task
//! becomes runnable or a registered I/O source is ready. It is preserved here
//! intact for the future embedded target and is only compiled under
//! `--features runtime-embassy`.
//!
//! NOTE for whoever wires this up: this path needs a *non-blocking* capture
//! source plus readiness notification, whereas the hosted `os::Source` now
//! opens a blocking socket for the thread-pool runtime. Re-introduce the
//! `O_NONBLOCK` + `Source::readable` pairing (the readiness plumbing below is
//! kept for exactly that) before driving `Executor::run` here.

use core::future::poll_fn;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::Poll;

use embassy_executor::Spawner;
use embassy_executor::raw;
use embassy_sync::waitqueue::AtomicWaker;

// Single-threaded critical section: no interrupts to manage in Linux userspace.
// Sound only because this runtime never runs handlers on more than one thread.
struct CritSec;
critical_section::set_impl!(CritSec);
unsafe impl critical_section::Impl for CritSec {
    unsafe fn acquire() -> critical_section::RawRestoreState {}
    unsafe fn release(_: critical_section::RawRestoreState) {}
}

/// Drives the executor to sleep when no task can make progress, and back awake
/// when one can. Everything OS-specific -- epoll/eventfd on Linux, IOCP on
/// Windows, WFE on bare metal -- lives behind this trait so the executor itself
/// stays generic.
pub trait Reactor {
    /// Opaque pointer handed to `embassy_executor::raw::Executor::new` and passed
    /// back to the platform `__pender`, which uses it to unblock [`wait`](Reactor::wait)
    /// when a task is woken.
    fn pender_context(&self) -> *mut ();

    /// Block until the pender signals (a task became runnable) or a registered I/O
    /// source is ready, waking any tasks whose sources became ready, then return so
    /// the executor can poll again.
    fn wait(&self);
}

pub struct Executor {
    inner: raw::Executor,
}

impl Executor {
    pub fn new(pender_context: *mut ()) -> Self {
        Self {
            inner: raw::Executor::new(pender_context),
        }
    }

    pub fn run(&'static mut self, reactor: impl Reactor, init: impl FnOnce(Spawner)) -> ! {
        init(self.inner.spawner());
        loop {
            unsafe { self.inner.poll() };
            reactor.wait();
        }
    }
}

// ============================================================================
// Linux reactor: epoll over the eventfd (executor wakeups) and the capture
// socket. Readiness for the socket is published through the statics below,
// which the (future, non-blocking) `Source::readable` future consumes.
// ============================================================================

const TOKEN_EVENTFD: u64 = 0;
const TOKEN_SOCKET: u64 = 1;

// Set by the reactor when epoll reports the socket readable; consumed by the
// socket's readable future. Single-threaded executor, so the flag plus a single
// waker slot is enough -- task polls and `wait` never run concurrently.
static SOCKET_READY: AtomicBool = AtomicBool::new(false);
static SOCKET_WAKER: AtomicWaker = AtomicWaker::new();

/// Resolves once the capture socket has data to read, yielding to other tasks
/// in the meantime. The recv loop awaits this whenever a non-blocking read
/// returns `EAGAIN`.
pub async fn readable() {
    poll_fn(|cx| {
        if SOCKET_READY.swap(false, Ordering::AcqRel) {
            Poll::Ready(())
        } else {
            SOCKET_WAKER.register(cx.waker());
            Poll::Pending
        }
    })
    .await
}

#[cfg(feature = "linux")]
pub struct LinuxReactor {
    epoll_fd: i32,
    event_fd: i32,
}

#[cfg(feature = "linux")]
impl LinuxReactor {
    pub fn new(socket_fd: i32) -> Self {
        let event_fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        let epoll_fd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };

        let mut ev = libc::epoll_event {
            events: libc::EPOLLIN as u32,
            u64: TOKEN_EVENTFD,
        };
        unsafe { libc::epoll_ctl(epoll_fd, libc::EPOLL_CTL_ADD, event_fd, &mut ev) };

        let mut ev = libc::epoll_event {
            events: libc::EPOLLIN as u32,
            u64: TOKEN_SOCKET,
        };
        unsafe { libc::epoll_ctl(epoll_fd, libc::EPOLL_CTL_ADD, socket_fd, &mut ev) };

        Self { epoll_fd, event_fd }
    }
}

#[cfg(feature = "linux")]
impl Reactor for LinuxReactor {
    fn pender_context(&self) -> *mut () {
        self.event_fd as usize as *mut ()
    }

    fn wait(&self) {
        let mut events = [libc::epoll_event { events: 0, u64: 0 }; 8];
        let n =
            unsafe { libc::epoll_wait(self.epoll_fd, events.as_mut_ptr(), events.len() as i32, -1) };

        for ev in &events[..n.max(0) as usize] {
            match ev.u64 {
                TOKEN_EVENTFD => {
                    // Drain the counter so the next epoll_wait blocks correctly.
                    let mut _val = 0u64;
                    unsafe { libc::read(self.event_fd, &mut _val as *mut _ as _, 8) };
                }
                TOKEN_SOCKET => {
                    SOCKET_READY.store(true, Ordering::Release);
                    SOCKET_WAKER.wake();
                }
                _ => {}
            }
        }
    }
}

// Called by embassy when any task's waker fires. Writes to the eventfd so the
// reactor's epoll_wait unblocks and the executor polls again.
// Must NOT call poll() directly -- see embassy_executor::raw::Executor docs.
#[cfg(feature = "linux")]
#[unsafe(export_name = "__pender")]
fn __pender(context: *mut ()) {
    let event_fd = context as usize as i32;
    let one = 1u64;
    unsafe { libc::write(event_fd, &one as *const _ as *const libc::c_void, 8) };
}

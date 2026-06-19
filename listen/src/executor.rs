use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::Waker;

const TOKEN_EVENTFD: u64 = 0;
const TOKEN_SOCKET: u64 = 1;

// Holds the waker registered by recv_loop when no packet is available.
// Written by recv_loop (task context), read by the epoll event handler
// (executor loop). Safe because the executor is single-threaded.
pub struct WakerSlot {
    occupied: AtomicBool,
    waker: UnsafeCell<MaybeUninit<Waker>>,
}

unsafe impl Sync for WakerSlot {}

impl WakerSlot {
    const fn new() -> Self {
        Self {
            occupied: AtomicBool::new(false),
            waker: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    pub fn store(&self, waker: &Waker) {
        // Drop any previous waker that was stored but never woken.
        if self.occupied.load(Ordering::Relaxed) {
            unsafe { (*self.waker.get()).assume_init_drop() };
        }
        unsafe { (*self.waker.get()).write(waker.clone()) };
        self.occupied.store(true, Ordering::Release);
    }

    pub fn wake(&self) {
        if self.occupied.swap(false, Ordering::AcqRel) {
            // assume_init_read moves the waker out; wake() consumes it.
            let waker = unsafe { (*self.waker.get()).assume_init_read() };
            waker.wake();
        }
    }
}

pub static SOCKET_WAKER: WakerSlot = WakerSlot::new();

// Set to true by the executor when epoll reports the socket is readable.
// Checked by recv_loop's poll_fn so it can return Ready and retry try_recv().
pub static SOCKET_READY: AtomicBool = AtomicBool::new(false);

pub struct Executor {
    inner: embassy_executor::raw::Executor,
    epoll_fd: i32,
    event_fd: i32,
}

impl Executor {
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

        Self {
            inner: embassy_executor::raw::Executor::new(event_fd as usize as *mut ()),
            epoll_fd,
            event_fd,
        }
    }

    pub fn run(&'static mut self, init: impl FnOnce(embassy_executor::Spawner)) -> ! {
        init(self.inner.spawner());

        let mut events = [libc::epoll_event { events: 0, u64: 0 }; 8];
        loop {
            unsafe { self.inner.poll() };

            let n = unsafe {
                libc::epoll_wait(self.epoll_fd, events.as_mut_ptr(), events.len() as i32, -1)
            };

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
}

// Called by embassy when any task's waker fires. Writes to the eventfd so
// epoll_wait unblocks and poll() runs again.
// Must NOT call poll() directly — see embassy_executor::raw::Executor docs.
#[unsafe(export_name = "__pender")]
fn __pender(context: *mut ()) {
    let event_fd = context as usize as i32;
    let one = 1u64;
    unsafe { libc::write(event_fd, &one as *const _ as *const libc::c_void, 8) };
}

//! Windows backend seam -- not yet implemented.
//!
//! This must call `windows-sys` directly rather than going through `rustix` (which itself only
//! emulates POSIX on top of WinSock). The pthread backend's shape (`pthread.rs`) is the template:
//! thread-per-packet, capped at `max_in_flight` concurrent handlers via a counting semaphore
//! (`try_acquire`/`acquire`/`release`), no pool and no queue. The Windows equivalents are
//! `CreateThread` (detached -- no `CloseHandle`-then-join, matching `pthread_detach`) for `spawn`
//! and a Win32 semaphore (`CreateSemaphoreW`/`WaitForSingleObject`/`ReleaseSemaphore`) in place of
//! `sem_init`/`sem_wait`/`sem_post`.
//!
//! Also blocked on `os::windows` not being wired into `os.rs` yet, so there is no `PacketSource`
//! for this backend to drive regardless.

use crate::source::{ListenError, PacketSource};

pub fn run<S, H>(_src: S, _handler: H, _max_in_flight: usize) -> Result<(), ListenError>
where
    S: PacketSource,
    H: Fn(&[u8]) + Send + Sync + 'static,
{
    todo!(
        "windows thread-per-packet runtime: windows-sys CreateThread + SRWLOCK/CONDITION_VARIABLE gate"
    )
}

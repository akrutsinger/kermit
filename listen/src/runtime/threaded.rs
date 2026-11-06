//! Thread-per-packet runtime for hosted OSes, split per OS the same way `os` is: the
//! recv-loop/spawn/cap shape is OS-agnostic, but the spawn and synchronization primitives
//! underneath it are not, so each OS gets its own complete implementation behind the same `run`
//! signature rather than a shared `Thread`/`Mutex` abstraction with one real caller.
//!
//!   pthread: POSIX pthreads via `libc` (Linux/macOS/*BSD); the hosted default.
//!   windows: windows-sys threads, direct per ADR-0002 (future; the module is
//!            preserved as a seam, not yet reachable -- see `windows.rs`).

#[cfg(unix)]
mod pthread;
#[cfg(unix)]
pub use pthread::run;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::run;

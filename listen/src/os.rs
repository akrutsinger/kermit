//! Per-OS packet-capture backends, selected by the compile target (ADR-0008). Process glue
//! (allocator, abort, entry point) lives in the platform layer, `common` (ADR-0009).
//!
//! Every backend type-checks for its own target (`scripts/check-targets.sh`); only Linux has been
//! run on real hardware, so `main.rs` refuses to build the binary anywhere else.

#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    windows
)))]
compile_error!("listen: no OS backend for this target yet");

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{FILTER, Source};

#[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd"))]
mod bsd;
#[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd"))]
pub use bsd::{FILTER, Source};

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{FILTER, Source};

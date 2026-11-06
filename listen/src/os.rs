//! Per-OS packet-capture backends, selected by the compile target (ADR-0008). Process glue
//! (allocator, abort, entry point) lives in the platform layer, `common` (ADR-0009).

#[cfg(not(target_os = "linux"))]
compile_error!("listen: no OS backend for this target yet");

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{FILTER, Source};

// #[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd"))]
// mod bsd;
// #[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd"))]
// pub use bsd::{FILTER, Source};

// #[cfg(windows)]
// mod windows;
// #[cfg(windows)]
// pub use windows::{FILTER, Source};

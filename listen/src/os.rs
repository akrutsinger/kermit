//! Per-OS backends, selected by the compile target (ADR-0008).

#[cfg(not(target_os = "linux"))]
compile_error!("listen: no OS backend for this target yet");

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{Alloc, FILTER, Source, abort, entry};

// #[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd"))]
// mod bsd;
// #[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd"))]
// pub use bsd::{Alloc, FILTER, Source, abort, entry};

// #[cfg(windows)]
// mod windows;
// #[cfg(windows)]
// pub use windows::{Alloc, FILTER, Source, abort, entry};

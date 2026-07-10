//! Concurrency runtime, selected at compile time and orthogonal to the OS axis in `os`. Exactly one
//! runtime feature must be enabled:
//!
//!   runtime-threads: one OS thread per packet, capped by the caller; the
//!                    hosted default.
//!   runtime-embassy: embassy async executor for embedded (future; the module
//!                    is preserved as a seam and not built by default).

#[cfg(not(any(feature = "runtime-threads", feature = "runtime-embassy")))]
compile_error!("listen: enable exactly one runtime feature: runtime-threads | runtime-embassy");

#[cfg(all(feature = "runtime-threads", feature = "runtime-embassy"))]
compile_error!("listen: runtime features are mutually exclusive; enable only one");

#[cfg(feature = "runtime-threads")]
mod threaded;
#[cfg(feature = "runtime-threads")]
pub use threaded::run;

#[cfg(feature = "runtime-embassy")]
mod embassy;

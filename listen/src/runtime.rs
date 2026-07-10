//! Concurrency runtime, selected at compile time and orthogonal to the OS axis in `os`.
//!
//! `runtime-threads` (one OS thread per packet, capped by the caller) is the only runtime today.
//! The embedded async runtime was removed until a concrete target is chosen (ADR-0007); rebuilding
//! it reintroduces a second arm on this axis.

#[cfg(not(feature = "runtime-threads"))]
compile_error!("listen: enable the runtime-threads feature");

#[cfg(feature = "runtime-threads")]
mod threaded;
#[cfg(feature = "runtime-threads")]
pub use threaded::run;

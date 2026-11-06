//! Concurrency runtime, selected by the compile target (ADR-0010): thread-per-packet on hosted OSes,
//! and on bare metal an async executor that waits on a concrete board (ADR-0007).

#[cfg(any(unix, windows))]
mod threaded;
#[cfg(any(unix, windows))]
pub use threaded::run;

#[cfg(target_os = "none")]
mod bare;
#[cfg(target_os = "none")]
pub use bare::run;

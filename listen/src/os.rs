#[cfg(not(any(
    feature = "linux",
    feature = "macos",
    feature = "freebsd",
    feature = "openbsd",
    feature = "windows",
)))]
compile_error!(
    "listen: enable exactly one OS feature: linux | macos | freebsd | openbsd | windows"
);

#[cfg(any(
    all(feature = "linux", feature = "macos"),
    all(feature = "linux", feature = "freebsd"),
    all(feature = "linux", feature = "openbsd"),
    all(feature = "linux", feature = "windows"),
    all(feature = "macos", feature = "freebsd"),
    all(feature = "macos", feature = "openbsd"),
    all(feature = "macos", feature = "windows"),
    all(feature = "freebsd", feature = "openbsd"),
    all(feature = "freebsd", feature = "windows"),
    all(feature = "openbsd", feature = "windows"),
))]
compile_error!("listen: OS features are mutually exclusive; enable only one");

#[cfg(feature = "linux")]
mod linux;
#[cfg(feature = "linux")]
pub use linux::{Alloc, FILTER, Source, abort, entry};

// #[cfg(any(feature = "macos", feature = "freebsd", feature = "openbsd"))]
// mod bsd;
// #[cfg(any(feature = "macos", feature = "freebsd", feature = "openbsd"))]
// pub use bsd::{Alloc, FILTER, Source, abort, entry};

// #[cfg(feature = "windows")]
// mod windows;
// #[cfg(feature = "windows")]
// pub use windows::{Alloc, FILTER, Source, abort, entry};

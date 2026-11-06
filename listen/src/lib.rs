//! `listen`'s per-OS plumbing (packet source, filter, concurrency runtime, process glue). The
//! `listen` binary in `main.rs` is only the one-per-program entry glue on top of this.
#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod filter;
pub mod os;
pub mod runtime;
pub mod source;

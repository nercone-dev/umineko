//! WASI provider.

#![cfg(target_os = "wasi")]

extern crate alloc;

pub mod wasi;

#[cfg(feature = "tcp")]
pub mod tcp;
#[cfg(feature = "udp")]
pub mod udp;
#[cfg(feature = "http")]
pub mod http;

pub use wasi::{WASIProvider};

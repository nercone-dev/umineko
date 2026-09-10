//! xxHash hashes.

#![no_std]
#![allow(non_camel_case_types)]

#[cfg(feature = "xxh32")]
pub mod xxh32;
#[cfg(feature = "xxh64")]
pub mod xxh64;
#[cfg(feature = "xxh3")]
pub mod xxh3;

#[cfg(feature = "xxh32")]
pub use xxh32::{XXH32};
#[cfg(feature = "xxh64")]
pub use xxh64::{XXH64};
#[cfg(feature = "xxh3")]
pub use xxh3::{XXH3, XXH3_64, XXH3_128};

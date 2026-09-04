//! RIPEMD message digests.

#![no_std]

#[cfg(feature = "ripemd160")]
pub mod ripemd160;

#[cfg(feature = "ripemd160")]
pub use ripemd160::{RIPEMD160};

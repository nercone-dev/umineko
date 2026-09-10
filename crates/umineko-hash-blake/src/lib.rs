//! BLAKE hash functions.

#![no_std]

#[cfg(feature = "blake2")]
pub mod blake2;
#[cfg(feature = "blake3")]
pub mod blake3;

#[cfg(feature = "blake2")]
pub use blake2::{BLAKE2, BLAKE2S, BLAKE2B};
#[cfg(feature = "blake3")]
pub use blake3::{BLAKE3};

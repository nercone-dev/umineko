//! ChaCha20.

#![no_std]

extern crate alloc;

pub mod errors;
pub mod chacha20;

pub use errors::{ChaCha20Error};
pub use chacha20::{ChaCha20, XChaCha20};

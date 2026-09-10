//! ChaCha20 and ChaCha20-Poly1305.

#![no_std]

extern crate alloc;

pub mod errors;
pub mod chacha20;
pub mod chacha20poly1305;

pub use errors::{ChaCha20Error};
pub use chacha20::{ChaCha20, XChaCha20};
pub use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};

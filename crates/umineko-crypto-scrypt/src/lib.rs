//! scrypt.

#![no_std]

extern crate alloc;

pub mod errors;
pub mod scrypt;
#[cfg(feature = "hmac")]
pub mod hmac;

pub use errors::{ScryptError};
pub use scrypt::{PRF, Scrypt};

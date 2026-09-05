//! PBKDF2.

#![no_std]

extern crate alloc;

pub mod errors;
pub mod pbkdf2;
#[cfg(feature = "hmac")]
pub mod hmac;

pub use errors::{PBKDF2Error};
pub use pbkdf2::{PRF, PBKDF2};

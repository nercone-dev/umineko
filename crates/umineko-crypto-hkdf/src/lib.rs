//! HKDF.

#![no_std]

extern crate alloc;

pub mod errors;
pub mod hkdf;
#[cfg(feature = "hmac")]
pub mod hmac;

pub use errors::{HKDFError};
pub use hkdf::{PRF, HKDF};

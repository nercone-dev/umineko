//! HMAC keyed hash.

#![no_std]

pub mod errors;
pub mod digest;
pub mod hmac;

pub use errors::{HMACError};
pub use digest::{Digest};
pub use hmac::{HMAC, HMACBuffer, HMACFunction};

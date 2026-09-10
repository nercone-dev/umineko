//! HMAC.

#![no_std]

extern crate alloc;

pub mod errors;
pub mod hmac;

pub use errors::{HMACError};
pub use hmac::{HMACHash, HMAC};

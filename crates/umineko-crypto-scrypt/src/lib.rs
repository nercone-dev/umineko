//! scrypt.

#![no_std]

extern crate alloc;

pub mod errors;
pub mod scrypt;

pub use errors::{ScryptError};
pub use scrypt::{PRF, Scrypt};

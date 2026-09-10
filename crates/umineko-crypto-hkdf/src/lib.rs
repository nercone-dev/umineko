//! HKDF.

#![no_std]

extern crate alloc;

pub mod errors;
pub mod hkdf;

pub use errors::{HKDFError};
pub use hkdf::{PRF, HKDF};

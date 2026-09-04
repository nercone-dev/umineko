//! Argon2.

#![no_std]

extern crate alloc;

pub mod errors;
pub mod argon2;

pub use errors::{Argon2Error};
pub use argon2::{Argon2, Argon2Variant};

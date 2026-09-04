//! PBKDF2.

#![no_std]

pub mod errors;
pub mod pbkdf2;

pub use errors::{PBKDF2Error};
pub use pbkdf2::{PRF, PBKDF2};

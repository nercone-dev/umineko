//! CMAC.

#![no_std]

extern crate alloc;

pub mod errors;
pub mod cmac;

pub use errors::{CMACError};
pub use cmac::{CMACCipher, CMAC};

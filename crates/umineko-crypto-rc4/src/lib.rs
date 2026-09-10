//! RC4.

#![no_std]

extern crate alloc;

pub mod errors;
pub mod rc4;

pub use errors::{RC4Error};
pub use rc4::{RC4};

//! RC2.

#![no_std]

extern crate alloc;

pub mod errors;
pub mod rc2;

pub use errors::{RC2Error};
pub use rc2::{RC2Mode, RC2Variant, RC2};

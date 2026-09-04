//! Ascon.

#![no_std]

extern crate alloc;

pub mod errors;
pub mod ascon;

pub use errors::{AsconError};
pub use ascon::{AsconAEAD128, AsconHash256, AsconXOF128, AsconCXOF128};

//! SEED.

#![no_std]

extern crate alloc;

pub mod errors;
pub mod seed;

pub use errors::{SEEDError};
pub use seed::{SEEDMode, SEED};

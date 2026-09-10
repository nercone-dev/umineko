//! AEGIS.

#![no_std]

extern crate alloc;

pub mod errors;
pub mod aegis;

pub use errors::{AEGISError};
pub use aegis::{AEGIS128L, AEGIS256};

//! ARIA.

#![no_std]

extern crate alloc;

pub mod errors;
pub mod aria;

pub use errors::{ARIAError};
pub use aria::{ARIA, ARIAMode, ARIA128, ARIA192, ARIA256};

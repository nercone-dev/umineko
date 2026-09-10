//! KBKDF (NIST SP 800-108).

#![no_std]

extern crate alloc;

pub mod errors;
pub mod kbkdf;

pub use errors::{KBKDFError};
pub use kbkdf::{PRF, KBKDFMode, KBKDF};

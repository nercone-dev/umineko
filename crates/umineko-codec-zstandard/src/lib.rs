//! Zstandard compression.

#![no_std]

extern crate alloc;

pub mod errors;
pub mod zstandard;

pub use errors::{ZstandardError};
pub use zstandard::{Zstandard, ZstandardEncoder, ZstandardDecoder};

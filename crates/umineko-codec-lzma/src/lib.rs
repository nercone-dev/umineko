//! LZMA compression.

#![no_std]

extern crate alloc;

pub mod errors;
pub mod lzma;

pub use errors::{LZMAError};
pub use lzma::{LZMA, LZMAEncoder, LZMADecoder, LZMAProperties};

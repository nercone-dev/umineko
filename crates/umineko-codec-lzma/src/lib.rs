//! LZMA compression.

#![no_std]

extern crate alloc;

pub mod errors;
pub mod lzma;

pub use errors::{LZMAError};
pub use lzma::{LZMA, LZMADecoder, LZMAEncoder, LZMALengths, LZMAMatcher, LZMAModel, LZMAProperties, LZMARangeDecoder, LZMARangeEncoder};

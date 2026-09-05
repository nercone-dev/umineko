//! LZ77 compression.

#![no_std]

extern crate alloc;

pub mod errors;
pub mod lz77;

pub use errors::{LZ77Error};
pub use lz77::{LZ77, LZ77Decoder, LZ77Encoder, LZ77Matcher};

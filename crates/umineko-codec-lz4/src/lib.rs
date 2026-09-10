//! LZ4 compression.

#![no_std]

extern crate alloc;

pub mod errors;
pub mod lz4;

pub use errors::{LZ4Error};
pub use lz4::{LZ4, LZ4Encoder, LZ4Decoder};

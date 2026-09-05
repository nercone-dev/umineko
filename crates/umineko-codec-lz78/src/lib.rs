//! LZ78 compression.

#![no_std]

extern crate alloc;

pub mod errors;
pub mod lz78;

pub use errors::{LZ78Error};
pub use lz78::{LZ78, LZ78Decoder, LZ78Dictionary, LZ78Encoder};

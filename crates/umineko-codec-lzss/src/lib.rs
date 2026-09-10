//! LZSS compression.

#![no_std]

extern crate alloc;

pub mod errors;
pub mod lzss;

pub use errors::{LZSSError};
pub use lzss::{LZSS, LZSSEncoder, LZSSDecoder};

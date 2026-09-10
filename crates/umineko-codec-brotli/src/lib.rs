//! Brotli compression.

#![no_std]

extern crate alloc;

pub mod errors;
pub mod brotli;

pub use errors::{BrotliError};
pub use brotli::{Brotli, BrotliEncoder, BrotliDecoder};

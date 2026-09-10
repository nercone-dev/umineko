//! Run-length encoding.

#![no_std]

extern crate alloc;

pub mod errors;
pub mod rle;

pub use errors::{RLEError};
pub use rle::{RLE, RLEEncoder, RLEDecoder};

//! DEFLATE compression.

#![no_std]

extern crate alloc;

pub mod errors;
pub mod deflate;

pub use errors::{DeflateError};
pub use deflate::{Deflate, DeflateEncoder, DeflateDecoder};

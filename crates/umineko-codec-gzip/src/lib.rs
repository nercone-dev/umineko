//! gzip compression.

#![no_std]

extern crate alloc;

pub mod errors;
pub mod gzip;

pub use errors::{GzipError};
pub use gzip::{Gzip, GzipEncoder, GzipDecoder, GzipHeader};

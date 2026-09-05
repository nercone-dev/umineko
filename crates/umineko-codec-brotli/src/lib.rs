//! Brotli compression.

#![no_std]

extern crate alloc;

pub mod errors;
pub mod contexts;
pub mod dictionary;
pub mod transforms;
pub mod brotli;

pub use errors::{BrotliError};
pub use contexts::{BrotliContext};
pub use dictionary::{BrotliDictionary};
pub use transforms::{BrotliChange, BrotliTransform};
pub use brotli::{Brotli, BrotliCode, BrotliCommand, BrotliDecoder, BrotliDistances, BrotliEncoder, BrotliMark, BrotliMeta, BrotliReader, BrotliSwitch, BrotliWriter};

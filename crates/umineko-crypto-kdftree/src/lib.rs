//! KDF_TREE.

#![no_std]

extern crate alloc;

pub mod errors;
pub mod kdftree;

pub use errors::{KDFTreeError};
pub use kdftree::{PRF, KDFTree};

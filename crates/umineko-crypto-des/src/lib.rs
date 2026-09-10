//! DES and Triple DES.

#![no_std]

extern crate alloc;

pub mod errors;
pub mod des;

pub use errors::{DESError};
pub use des::{DESMode, DES, TripleDES};

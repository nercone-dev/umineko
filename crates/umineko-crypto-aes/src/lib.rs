//! AES.

#![no_std]

extern crate alloc;

pub mod errors;
pub mod aes;

pub use errors::{AESError};
pub use aes::{AES, AESMode, AES128, AES192, AES256};

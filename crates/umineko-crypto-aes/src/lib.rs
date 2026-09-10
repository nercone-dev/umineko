//! AES.

#![no_std]
#![allow(non_camel_case_types)]

extern crate alloc;

pub mod errors;
pub mod aes;

pub use errors::{AESError};
pub use aes::{AES, AESMode, AES128, AES192, AES256};

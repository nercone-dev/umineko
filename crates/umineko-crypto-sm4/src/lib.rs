//! SM4.

#![no_std]

extern crate alloc;

pub mod errors;
pub mod sm4;

pub use errors::{SM4Error};
pub use sm4::{SM4Mode, SM4};

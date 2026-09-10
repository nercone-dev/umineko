//! SM2.

#![no_std]

extern crate alloc;

pub mod errors;
pub mod sm2;

pub use errors::{SM2Error};
pub use sm2::{SM2, SM2PrivateKey, SM2PublicKey, SM2Signature};

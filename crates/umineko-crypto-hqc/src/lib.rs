//! HQC.

#![no_std]

extern crate alloc;

pub mod errors;
pub mod hqc;

pub use errors::{HQCError};
pub use hqc::{HQC, HQCPrivateKey, HQCPublicKey, HQCCiphertext, HQCSharedSecret};

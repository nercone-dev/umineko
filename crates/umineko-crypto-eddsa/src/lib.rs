//! EdDSA.

#![no_std]

extern crate alloc;

pub mod errors;
pub mod eddsa;

pub use errors::{EdDSAError};
pub use eddsa::{EdDSA, EdDSAPrivateKey, EdDSAPublicKey, EdDSASignature};

//! ECDSA.

#![no_std]

extern crate alloc;

pub mod errors;
pub mod ecdsa;

pub use errors::{ECDSAError};
pub use ecdsa::{ECDSA, ECDSAPrivateKey, ECDSAPublicKey, ECDSASignature};

//! ML-DSA.

#![no_std]

extern crate alloc;

pub mod errors;
pub mod mldsa;

pub use errors::{MLDSAError};
pub use mldsa::{MLDSA, MLDSAPrivateKey, MLDSAPublicKey, MLDSASignature};

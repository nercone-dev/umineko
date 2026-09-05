//! HQC.

#![no_std]

extern crate alloc;

pub mod errors;
pub mod field;
pub mod code;
pub mod hqc;

pub use errors::{HQCError};
pub use field::{GF256};
pub use code::{ReedMuller, ReedSolomon};
pub use hqc::{HQC, HQCStream, HQCPrivateKey, HQCPublicKey, HQCCiphertext, HQCSharedSecret};

//! SLH-DSA.

#![no_std]
#![allow(non_camel_case_types)]

extern crate alloc;

pub mod errors;
pub mod slhdsa;

pub use errors::{SLHDSAError};
pub use slhdsa::{SLHDSA, SLHDSAAddress, SLHDSAPart, SLHDSAPrivateKey, SLHDSAPublicKey, SLHDSASignature};

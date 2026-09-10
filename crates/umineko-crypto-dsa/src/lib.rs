//! DSA.

#![no_std]
#![allow(non_camel_case_types)]

extern crate alloc;

pub mod errors;
pub mod dsa;

pub use errors::{DSAError};
pub use dsa::{DSA, DSAPrivateKey, DSAPublicKey, DSASignature};

//! ECCSI.

#![no_std]

extern crate alloc;

pub mod errors;
pub mod eccsi;

pub use errors::{ECCSIError};
pub use eccsi::{ECCSI, ECCSIMasterKey, ECCSIPublicKey, ECCSISigningKey, ECCSISignature};

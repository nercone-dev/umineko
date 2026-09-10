//! GOST R 34.10-2012.

#![no_std]

extern crate alloc;

pub mod errors;
pub mod gostr3410;

pub use errors::{GOSTR3410Error};
pub use gostr3410::{GOSTR3410, GOSTR3410PrivateKey, GOSTR3410PublicKey, GOSTR3410Signature, GOSTR3410SharedSecret};

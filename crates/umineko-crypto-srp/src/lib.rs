//! SRP-6a.

#![no_std]

extern crate alloc;

pub mod errors;
pub mod srp;

pub use errors::{SRPError};
pub use srp::{SRPGroup, SRPVerifier, SRPClient, SRPServer};

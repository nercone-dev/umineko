//! SipHash keyed hash.

#![no_std]

pub mod siphash;

pub use siphash::{SipHash, SipHashRounds};

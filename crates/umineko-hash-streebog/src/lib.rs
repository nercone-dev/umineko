//! Streebog (GOST R 34.11-2012) message digests.

#![no_std]

pub mod streebog;

pub use streebog::{Streebog, Streebog256, Streebog512};

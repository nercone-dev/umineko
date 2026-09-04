//! Poly1305.

#![no_std]

pub mod errors;
pub mod poly1305;

pub use errors::{Poly1305Error};
pub use poly1305::{Poly1305};

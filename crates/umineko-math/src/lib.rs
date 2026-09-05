//! Arbitrary precision arithmetic and elliptic curves.

#![no_std]

extern crate alloc;

pub mod errors;
#[cfg(feature = "integer")]
pub mod integer;
#[cfg(feature = "modulus")]
pub mod modulus;
#[cfg(feature = "prime")]
pub mod prime;
#[cfg(feature = "weierstrass")]
pub mod weierstrass;
#[cfg(feature = "edwards")]
pub mod edwards;
#[cfg(feature = "ladder")]
pub mod ladder;

pub use errors::{MathError};
#[cfg(feature = "integer")]
pub use integer::{Integer};
#[cfg(feature = "modulus")]
pub use modulus::{Modulus, Residue};
#[cfg(feature = "prime")]
pub use prime::{Prime};
#[cfg(feature = "weierstrass")]
pub use weierstrass::{Weierstrass, WeierstrassPoint};
#[cfg(feature = "edwards")]
pub use edwards::{Edwards, EdwardsPoint};
#[cfg(feature = "ladder")]
pub use ladder::{Ladder};

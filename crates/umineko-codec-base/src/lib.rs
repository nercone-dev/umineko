//! Base16, Base32, Base58, Base64 and Base85 encodings.

#![no_std]

extern crate alloc;

pub mod errors;
#[cfg(feature = "base16")]
pub mod base16;
#[cfg(feature = "base32")]
pub mod base32;
#[cfg(feature = "base58")]
pub mod base58;
#[cfg(feature = "base64")]
pub mod base64;
#[cfg(feature = "base85")]
pub mod base85;

pub use errors::{BaseError};
#[cfg(feature = "base16")]
pub use base16::{Base16};
#[cfg(feature = "base32")]
pub use base32::{Base32, Base32Alphabet};
#[cfg(feature = "base58")]
pub use base58::{Base58, Base58Alphabet};
#[cfg(feature = "base64")]
pub use base64::{Base64, Base64Alphabet};
#[cfg(feature = "base85")]
pub use base85::{Base85, Base85Alphabet};

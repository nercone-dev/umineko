//! SHA message digests.

#![no_std]
#![allow(non_camel_case_types)]

#[cfg(feature = "sha0")]
pub mod sha0;
#[cfg(feature = "sha1")]
pub mod sha1;
#[cfg(feature = "sha2")]
pub mod sha2;
#[cfg(feature = "sha3")]
pub mod sha3;

#[cfg(feature = "sha0")]
pub use sha0::{SHA0};
#[cfg(feature = "sha1")]
pub use sha1::{SHA1};
#[cfg(feature = "sha2")]
pub use sha2::{SHA2, SHA2_224, SHA2_256, SHA2_384, SHA2_512, SHA2_512_224, SHA2_512_256};
#[cfg(feature = "sha3")]
pub use sha3::{SHA3, SHA3_224, SHA3_256, SHA3_384, SHA3_512, SHAKE, SHAKE128, SHAKE256};

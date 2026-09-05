//! Hash functions.

#![no_std]

#[cfg(feature = "md")]
pub use umineko_hash_md as md;
#[cfg(feature = "sha")]
pub use umineko_hash_sha as sha;
#[cfg(feature = "xxhash")]
pub use umineko_hash_xxhash as xxhash;
#[cfg(feature = "blake")]
pub use umineko_hash_blake as blake;
#[cfg(feature = "ripemd")]
pub use umineko_hash_ripemd as ripemd;
#[cfg(feature = "crc")]
pub use umineko_hash_crc as crc;
#[cfg(feature = "siphash")]
pub use umineko_hash_siphash as siphash;
#[cfg(feature = "sm3")]
pub use umineko_hash_sm3 as sm3;
#[cfg(feature = "hmac")]
pub use umineko_hash_hmac as hmac;

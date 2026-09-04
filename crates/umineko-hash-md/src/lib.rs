//! MD message digests.

#![no_std]

#[cfg(feature = "md2")]
pub mod md2;
#[cfg(feature = "md4")]
pub mod md4;
#[cfg(feature = "md5")]
pub mod md5;
#[cfg(feature = "md6")]
pub mod md6;

#[cfg(feature = "md2")]
pub use md2::{MD2};
#[cfg(feature = "md4")]
pub use md4::{MD4};
#[cfg(feature = "md5")]
pub use md5::{MD5};
#[cfg(feature = "md6")]
pub use md6::{MD6};

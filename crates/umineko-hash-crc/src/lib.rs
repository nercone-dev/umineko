//! CRC and Adler checksums.

#![no_std]

#[cfg(feature = "crc16")]
pub mod crc16;
#[cfg(feature = "crc32")]
pub mod crc32;
#[cfg(feature = "crc32c")]
pub mod crc32c;
#[cfg(feature = "adler32")]
pub mod adler32;

#[cfg(feature = "crc16")]
pub use crc16::{CRC16, CRC16Parameters, CRC16Table};
#[cfg(feature = "crc32")]
pub use crc32::{CRC32, CRC32Parameters, CRC32Table};
#[cfg(feature = "crc32c")]
pub use crc32c::{CRC32C};
#[cfg(feature = "adler32")]
pub use adler32::{Adler32};

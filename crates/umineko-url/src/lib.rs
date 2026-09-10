//! URL parsing.

#![no_std]

extern crate alloc;

pub mod encoding;
pub mod errors;
pub mod types;

pub use encoding::{URLEncoding, Punycode};
pub use errors::{URLError};
pub use types::{URL, URLScheme, URLUserInfo, URLHost, URLPath, URLQuery};

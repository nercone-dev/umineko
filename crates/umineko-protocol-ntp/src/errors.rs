use alloc::string::String;
use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NTPError {
    Version,
    Header,
    Extension(String),
    Mismatch,
    Unsynchronized,
    Denied,
    Authentication,
    Sanity,
    Limit,
    Transport,
    Timeout,
}

impl fmt::Display for NTPError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl core::error::Error for NTPError {}

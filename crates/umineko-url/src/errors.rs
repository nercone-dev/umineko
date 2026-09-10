use alloc::string::String;
use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum URLError {
        Scheme(String),
        Host(String),
        Port(String),
        Encoding(String),
        Reference(String),
}

impl fmt::Display for URLError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl core::error::Error for URLError {}

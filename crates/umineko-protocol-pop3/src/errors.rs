use alloc::string::String;
use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum POP3Error {
    Syntax(String),
    State,
    Capability(String),
    Authentication,
    StartTLS,
    Locked,
    NotFound(u32),
    Failure(String),
    Limit,
    Closed,
    Transport,
    Timeout,
}

impl fmt::Display for POP3Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl core::error::Error for POP3Error {}

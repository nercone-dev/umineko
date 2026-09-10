use alloc::string::String;
use core::fmt;
use crate::types::CoAPCode;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoAPError {
    Version,
    Header,
    Option(String),
    CriticalOption(u16),
    Token,
    Response(CoAPCode),
    NotAcknowledged,
    Reset,
    Block(String),
    Limit,
    Transport,
    Timeout,
}

impl fmt::Display for CoAPError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl core::error::Error for CoAPError {}

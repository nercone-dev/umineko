use alloc::string::String;
use core::fmt;
use crate::types::FTPReplyCode;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FTPError {
    Syntax(String),
    State,
    Authentication,
    Secure,
    DataConnection,
    NotFound(String),
    Permission,
    Reply(FTPReplyCode),
    Listing(String),
    Limit,
    Closed,
    Transport,
    Timeout,
}

impl fmt::Display for FTPError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl core::error::Error for FTPError {}

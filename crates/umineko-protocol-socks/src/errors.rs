use alloc::string::String;
use core::fmt;
use crate::types::SOCKSReply;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SOCKSError {
    Version,
    Syntax,
    Method,
    Authentication,
    Address(String),
    Command,
    Reply(SOCKSReply),
    Limit,
    Closed,
    Transport,
    Timeout,
}

impl fmt::Display for SOCKSError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl core::error::Error for SOCKSError {}

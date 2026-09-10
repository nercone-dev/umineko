use alloc::string::String;
use core::fmt;
use crate::types::IMAPStatus;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IMAPError {
    Syntax(String),
    State,
    Capability(String),
    Authentication,
    StartTLS,
    Mailbox(String),
    Sequence(String),
    Status(IMAPStatus),
    Tag,
    Limit,
    Closed,
    Transport,
    Timeout,
}

impl fmt::Display for IMAPError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl core::error::Error for IMAPError {}

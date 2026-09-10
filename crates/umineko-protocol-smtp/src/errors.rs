use alloc::string::String;
use core::fmt;
use crate::types::SMTPReplyCode;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SMTPError {
    Syntax(String),
    State,
    Extension(String),
    Address(String),
    Authentication,
    StartTLS,
    Reply(SMTPReplyCode),
    Limit,
    MIME(String),
    Closed,
    Transport,
    Timeout,
}

impl fmt::Display for SMTPError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl core::error::Error for SMTPError {}

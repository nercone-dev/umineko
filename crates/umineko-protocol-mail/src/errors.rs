use alloc::string::String;
use core::fmt;

use umineko_protocol_dns::DNSError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MailError {
    Syntax(String),
    NotFound(String),
    Ambiguous(String),
    Lookup,
    Verification(String),
    Tampered,
    Expired,
    Algorithm(String),
    Limit,
    DNS(DNSError),
}

impl fmt::Display for MailError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl core::error::Error for MailError {}

impl From<DNSError> for MailError {
    fn from(error: DNSError) -> Self {
        Self::DNS(error)
    }
}

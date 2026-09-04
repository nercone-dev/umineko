use core::fmt;

use umineko_protocol_icmp::ICMPError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NDPError {
    Type,
    Option,
    Syntax,
    Truncated,
    Limit,
    HopLimit,
    Unresolved,
    Duplicate,
    ICMP(ICMPError),
    Timeout,
}

impl fmt::Display for NDPError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl core::error::Error for NDPError {}

impl From<ICMPError> for NDPError {
    fn from(error: ICMPError) -> Self {
        Self::ICMP(error)
    }
}

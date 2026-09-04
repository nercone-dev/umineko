use alloc::string::String;
use core::fmt;

use umineko_protocol_ip::IPError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DHCPError {
    Version,
    Header,
    Option(String),
    Mismatch,
    Exhausted,
    Declined,
    Expired,
    Duplicate,
    Limit,
    IP(IPError),
    Timeout,
}

impl fmt::Display for DHCPError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl core::error::Error for DHCPError {}

impl From<IPError> for DHCPError {
    fn from(error: IPError) -> Self {
        Self::IP(error)
    }
}

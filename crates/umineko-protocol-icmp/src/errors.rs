use core::fmt;

use umineko_protocol_ip::IPError;
use umineko_helpers::provider::ProviderError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ICMPError {
    Version,
    Type,
    Syntax,
    Checksum,
    Truncated,
    Limit,
    IP(IPError),
    Provider(ProviderError),
    Timeout,
}

impl fmt::Display for ICMPError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl core::error::Error for ICMPError {}

impl From<IPError> for ICMPError {
    fn from(error: IPError) -> Self {
        Self::IP(error)
    }
}

impl From<ProviderError> for ICMPError {
    fn from(error: ProviderError) -> Self {
        Self::Provider(error)
    }
}

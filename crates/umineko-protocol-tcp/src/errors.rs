use core::fmt;

use umineko_protocol_ip::IPError;
use umineko_helpers::provider::ProviderError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TCPError {
    Header,
    Option,
    Checksum,
    State,
    Refused,
    Reset,
    Limit,
    Closed,
    AddressInUse,
    IP(IPError),
    Provider(ProviderError),
    Timeout,
}

impl fmt::Display for TCPError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl core::error::Error for TCPError {}

impl From<IPError> for TCPError {
    fn from(error: IPError) -> Self {
        Self::IP(error)
    }
}

impl From<ProviderError> for TCPError {
    fn from(error: ProviderError) -> Self {
        Self::Provider(error)
    }
}

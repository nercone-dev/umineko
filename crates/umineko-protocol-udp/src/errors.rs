use core::fmt;

use umineko_protocol_ip::IPError;
use umineko_helpers::provider::ProviderError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UDPError {
    Header,
    Checksum,
    Length,
    Limit,
    Unreachable,
    Closed,
    AddressInUse,
    IP(IPError),
    Provider(ProviderError),
    Timeout,
}

impl fmt::Display for UDPError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl core::error::Error for UDPError {}

impl From<IPError> for UDPError {
    fn from(error: IPError) -> Self {
        Self::IP(error)
    }
}

impl From<ProviderError> for UDPError {
    fn from(error: ProviderError) -> Self {
        Self::Provider(error)
    }
}

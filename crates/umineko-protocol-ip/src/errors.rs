use core::fmt;

use umineko_helpers::provider::ProviderError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IPError {
    Version,
    Header,
    Checksum,
    Truncated,
    Limit,
    Fragmentation,
    TimeToLive,
    Route,
    Transport,
    Provider(ProviderError),
    Timeout,
}

impl fmt::Display for IPError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl core::error::Error for IPError {}

impl From<ProviderError> for IPError {
    fn from(error: ProviderError) -> Self {
        Self::Provider(error)
    }
}

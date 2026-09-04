use core::fmt;

use umineko_helpers::provider::ProviderError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LZ78Error {
        Format,
        Checksum,
        Limit,
        Truncated,
        Provider(ProviderError),
}

impl fmt::Display for LZ78Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl core::error::Error for LZ78Error {}

impl From<ProviderError> for LZ78Error {
    fn from(error: ProviderError) -> Self {
        match error {
            ProviderError::Format => Self::Format,
            ProviderError::Truncated => Self::Truncated,
            ProviderError::Limit => Self::Limit,
            other => Self::Provider(other),
        }
    }
}

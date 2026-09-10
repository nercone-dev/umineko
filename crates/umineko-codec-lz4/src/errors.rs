use core::fmt;

use umineko_helpers::provider::ProviderError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LZ4Error {
        Format,
        Checksum,
        Limit,
        Truncated,
        Provider(ProviderError),
}

impl fmt::Display for LZ4Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl core::error::Error for LZ4Error {}

impl From<ProviderError> for LZ4Error {
    fn from(error: ProviderError) -> Self {
        match error {
            ProviderError::Format => Self::Format,
            ProviderError::Truncated => Self::Truncated,
            ProviderError::Limit => Self::Limit,
            other => Self::Provider(other),
        }
    }
}

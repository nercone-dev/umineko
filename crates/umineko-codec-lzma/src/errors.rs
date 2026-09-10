use core::fmt;

use umineko_helpers::provider::ProviderError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LZMAError {
        Format,
        Checksum,
        Limit,
        Truncated,
        Properties,
        Provider(ProviderError),
}

impl fmt::Display for LZMAError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl core::error::Error for LZMAError {}

impl From<ProviderError> for LZMAError {
    fn from(error: ProviderError) -> Self {
        match error {
            ProviderError::Format => Self::Format,
            ProviderError::Truncated => Self::Truncated,
            ProviderError::Limit => Self::Limit,
            other => Self::Provider(other),
        }
    }
}

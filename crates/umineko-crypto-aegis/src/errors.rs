use core::fmt;

use umineko_helpers::provider::ProviderError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AEGISError {
    Key,
    Nonce,
    Tag,
    Length,
    Authentication,
    Provider(ProviderError),
}

impl fmt::Display for AEGISError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl core::error::Error for AEGISError {}

impl From<ProviderError> for AEGISError {
    fn from(error: ProviderError) -> Self {
        match error {
            ProviderError::Authentication => Self::Authentication,
            other => Self::Provider(other),
        }
    }
}

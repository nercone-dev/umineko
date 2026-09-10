use core::fmt;

use umineko_helpers::provider::ProviderError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsconError {
        Key,
        Nonce,
        Length,
        Padding,
        Authentication,
        Variant,
        Provider(ProviderError),
}

impl fmt::Display for AsconError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl core::error::Error for AsconError {}

impl From<ProviderError> for AsconError {
    fn from(error: ProviderError) -> Self {
        match error {
            ProviderError::Authentication => Self::Authentication,
            other => Self::Provider(other),
        }
    }
}

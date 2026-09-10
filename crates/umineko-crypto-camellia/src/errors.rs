use core::fmt;

use umineko_helpers::provider::ProviderError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CamelliaError {
    Key,
    Nonce,
    Length,
    Padding,
    Authentication,
    Variant,
    Provider(ProviderError),
}

impl fmt::Display for CamelliaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl core::error::Error for CamelliaError {}

impl From<ProviderError> for CamelliaError {
    fn from(error: ProviderError) -> Self {
        match error {
            ProviderError::Authentication => Self::Authentication,
            other => Self::Provider(other),
        }
    }
}

use core::fmt;

use umineko_helpers::provider::ProviderError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdDSAError {
        Variant,
        Key,
        Encoding,
        Length,
        Verification,
        Seed,
        Provider(ProviderError),
}

impl fmt::Display for EdDSAError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl core::error::Error for EdDSAError {}

impl From<ProviderError> for EdDSAError {
    fn from(error: ProviderError) -> Self {
        match error {
            ProviderError::Verification => Self::Verification,
            other => Self::Provider(other),
        }
    }
}

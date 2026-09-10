use core::fmt;

use umineko_helpers::provider::ProviderError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SLHDSAError {
        Variant,
        Key,
        Encoding,
        Length,
        Verification,
        Seed,
        Provider(ProviderError),
}

impl fmt::Display for SLHDSAError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl core::error::Error for SLHDSAError {}

impl From<ProviderError> for SLHDSAError {
    fn from(error: ProviderError) -> Self {
        match error {
            ProviderError::Verification => Self::Verification,
            other => Self::Provider(other),
        }
    }
}

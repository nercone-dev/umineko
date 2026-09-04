use core::fmt;

use umineko_helpers::provider::ProviderError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MLKEMError {
        Variant,
        Key,
        Encoding,
        Length,
        Verification,
        Seed,
        Provider(ProviderError),
}

impl fmt::Display for MLKEMError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl core::error::Error for MLKEMError {}

impl From<ProviderError> for MLKEMError {
    fn from(error: ProviderError) -> Self {
        match error {
            ProviderError::Verification => Self::Verification,
            other => Self::Provider(other),
        }
    }
}

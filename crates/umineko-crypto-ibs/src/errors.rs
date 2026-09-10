use core::fmt;

use umineko_helpers::provider::ProviderError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IBSError {
    Variant,
    Key,
    Identity,
    Encoding,
    Verification,
    Seed,
    Provider(ProviderError),
}

impl fmt::Display for IBSError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl core::error::Error for IBSError {}

impl From<ProviderError> for IBSError {
    fn from(error: ProviderError) -> Self {
        match error {
            ProviderError::Verification => Self::Verification,
            other => Self::Provider(other),
        }
    }
}

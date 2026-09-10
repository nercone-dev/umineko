use core::fmt;

use umineko_helpers::provider::ProviderError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DSAError {
    Key,
    Size,
    Encoding,
    Length,
    Verification,
    Seed,
    Provider(ProviderError),
}

impl fmt::Display for DSAError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl core::error::Error for DSAError {}

impl From<ProviderError> for DSAError {
    fn from(error: ProviderError) -> Self {
        match error {
            ProviderError::Verification => Self::Verification,
            other => Self::Provider(other),
        }
    }
}

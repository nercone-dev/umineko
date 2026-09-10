use core::fmt;

use umineko_helpers::provider::ProviderError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ECCSIError {
    Key,
    Identity,
    Encoding,
    Length,
    Verification,
    Seed,
    Provider(ProviderError),
}

impl fmt::Display for ECCSIError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl core::error::Error for ECCSIError {}

impl From<ProviderError> for ECCSIError {
    fn from(error: ProviderError) -> Self {
        match error {
            ProviderError::Verification => Self::Verification,
            other => Self::Provider(other),
        }
    }
}

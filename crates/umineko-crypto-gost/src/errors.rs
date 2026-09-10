use core::fmt;

use umineko_helpers::provider::ProviderError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GOSTError {
    Key,
    Nonce,
    Length,
    Padding,
    Authentication,
    Variant,
    Provider(ProviderError),
}

impl fmt::Display for GOSTError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl core::error::Error for GOSTError {}

impl From<ProviderError> for GOSTError {
    fn from(error: ProviderError) -> Self {
        match error {
            ProviderError::Authentication => Self::Authentication,
            other => Self::Provider(other),
        }
    }
}

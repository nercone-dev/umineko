use core::fmt;

use umineko_helpers::provider::ProviderError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RSAError {
        Key,
        Size,
        Encoding,
        Padding,
        Length,
        Verification,
        Seed,
        Provider(ProviderError),
}

impl fmt::Display for RSAError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl core::error::Error for RSAError {}

impl From<ProviderError> for RSAError {
    fn from(error: ProviderError) -> Self {
        match error {
            ProviderError::Verification => Self::Verification,
            other => Self::Provider(other),
        }
    }
}

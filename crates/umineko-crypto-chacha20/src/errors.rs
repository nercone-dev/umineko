use core::fmt;

use umineko_helpers::provider::ProviderError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChaCha20Error {
        Key,
        Nonce,
        Length,
        Padding,
        Authentication,
        Variant,
        Provider(ProviderError),
}

impl fmt::Display for ChaCha20Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl core::error::Error for ChaCha20Error {}

impl From<ProviderError> for ChaCha20Error {
    fn from(error: ProviderError) -> Self {
        match error {
            ProviderError::Authentication => Self::Authentication,
            other => Self::Provider(other),
        }
    }
}

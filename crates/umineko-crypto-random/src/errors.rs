use core::fmt;

use umineko_helpers::provider::ProviderError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RandomError {
    Strength,
    Entropy,
    Nonce,
    Personalization,
    Additional,
    Request,
    Reseed,
    Provider(ProviderError),
}

impl fmt::Display for RandomError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl core::error::Error for RandomError {}

impl From<ProviderError> for RandomError {
    fn from(error: ProviderError) -> Self {
        Self::Provider(error)
    }
}

use core::fmt;

use umineko_helpers::provider::ProviderError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HKDFError {
    Length,
    PseudorandomKey,
    Provider(ProviderError),
}

impl fmt::Display for HKDFError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl core::error::Error for HKDFError {}

impl From<ProviderError> for HKDFError {
    fn from(error: ProviderError) -> Self {
        Self::Provider(error)
    }
}

use core::fmt;

use umineko_helpers::provider::ProviderError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KDFTreeError {
    Length,
    Counter,
    Provider(ProviderError),
}

impl fmt::Display for KDFTreeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl core::error::Error for KDFTreeError {}

impl From<ProviderError> for KDFTreeError {
    fn from(error: ProviderError) -> Self {
        Self::Provider(error)
    }
}

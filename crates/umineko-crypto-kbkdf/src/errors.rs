use core::fmt;

use umineko_helpers::provider::ProviderError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KBKDFError {
    Key,
    Counter,
    Length,
    IV,
    Provider(ProviderError),
}

impl fmt::Display for KBKDFError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl core::error::Error for KBKDFError {}

impl From<ProviderError> for KBKDFError {
    fn from(error: ProviderError) -> Self {
        Self::Provider(error)
    }
}

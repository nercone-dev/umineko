use core::fmt;

use umineko_helpers::provider::ProviderError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IDEAError {
    Key,
    Nonce,
    Length,
    Padding,
    Provider(ProviderError),
}

impl fmt::Display for IDEAError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl core::error::Error for IDEAError {}

impl From<ProviderError> for IDEAError {
    fn from(error: ProviderError) -> Self {
        Self::Provider(error)
    }
}

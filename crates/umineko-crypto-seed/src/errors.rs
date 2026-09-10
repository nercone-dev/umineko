use core::fmt;

use umineko_helpers::provider::ProviderError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SEEDError {
    Key,
    Nonce,
    Length,
    Padding,
    Provider(ProviderError),
}

impl fmt::Display for SEEDError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl core::error::Error for SEEDError {}

impl From<ProviderError> for SEEDError {
    fn from(error: ProviderError) -> Self {
        Self::Provider(error)
    }
}

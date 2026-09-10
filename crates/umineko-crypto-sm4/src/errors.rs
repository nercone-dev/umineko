use core::fmt;

use umineko_helpers::provider::ProviderError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SM4Error {
    Key,
    Nonce,
    Length,
    Padding,
    Authentication,
    Provider(ProviderError),
}

impl fmt::Display for SM4Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl core::error::Error for SM4Error {}

impl From<ProviderError> for SM4Error {
    fn from(error: ProviderError) -> Self {
        match error {
            ProviderError::Authentication => Self::Authentication,
            other => Self::Provider(other),
        }
    }
}

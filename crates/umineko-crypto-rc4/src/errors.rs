use core::fmt;

use umineko_helpers::provider::ProviderError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RC4Error {
    Key,
    Length,
    Provider(ProviderError),
}

impl fmt::Display for RC4Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl core::error::Error for RC4Error {}

impl From<ProviderError> for RC4Error {
    fn from(error: ProviderError) -> Self {
        Self::Provider(error)
    }
}

use core::fmt;

use umineko_helpers::provider::ProviderError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RC2Error {
    Key,
    Nonce,
    Length,
    Padding,
    Variant,
    Provider(ProviderError),
}

impl fmt::Display for RC2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl core::error::Error for RC2Error {}

impl From<ProviderError> for RC2Error {
    fn from(error: ProviderError) -> Self {
        Self::Provider(error)
    }
}

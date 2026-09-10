use core::fmt;

use umineko_helpers::provider::ProviderError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Poly1305Error {
        Key,
        Nonce,
        Length,
        Padding,
        Authentication,
        Variant,
        Provider(ProviderError),
}

impl fmt::Display for Poly1305Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl core::error::Error for Poly1305Error {}

impl From<ProviderError> for Poly1305Error {
    fn from(error: ProviderError) -> Self {
        Self::Provider(error)
    }
}

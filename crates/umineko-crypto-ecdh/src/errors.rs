use core::fmt;

use umineko_helpers::provider::ProviderError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ECDHError {
        Curve,
        Key,
        Encoding,
        Point,
        SharedSecret,
        Seed,
        Provider(ProviderError),
}

impl fmt::Display for ECDHError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl core::error::Error for ECDHError {}

impl From<ProviderError> for ECDHError {
    fn from(error: ProviderError) -> Self {
        Self::Provider(error)
    }
}

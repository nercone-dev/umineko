use core::fmt;

use umineko_helpers::provider::ProviderError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SM2Error {
    Key,
    Encoding,
    Point,
    Identity,
    Verification,
    Seed,
    Provider(ProviderError),
}

impl fmt::Display for SM2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl core::error::Error for SM2Error {}

impl From<ProviderError> for SM2Error {
    fn from(error: ProviderError) -> Self {
        match error {
            ProviderError::Verification => Self::Verification,
            other => Self::Provider(other),
        }
    }
}

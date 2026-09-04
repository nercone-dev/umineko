use core::fmt;

use umineko_helpers::provider::ProviderError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Argon2Error {
    Variant,
    Parameters,
    Salt,
    Length,
    Memory,
    Provider(ProviderError),
}

impl fmt::Display for Argon2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl core::error::Error for Argon2Error {}

impl From<ProviderError> for Argon2Error {
    fn from(error: ProviderError) -> Self {
        Self::Provider(error)
    }
}

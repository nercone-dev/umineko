use core::fmt;

use umineko_helpers::provider::ProviderError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PBKDF2Error {
    Length,
    Iterations,
    Provider(ProviderError),
}

impl fmt::Display for PBKDF2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl core::error::Error for PBKDF2Error {}

impl From<ProviderError> for PBKDF2Error {
    fn from(error: ProviderError) -> Self {
        Self::Provider(error)
    }
}

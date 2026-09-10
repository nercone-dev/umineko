use core::fmt;

use umineko_helpers::provider::ProviderError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DHError {
    Group,
    Parameters,
    Key,
    Encoding,
    SharedSecret,
    Seed,
    Provider(ProviderError),
}

impl fmt::Display for DHError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl core::error::Error for DHError {}

impl From<ProviderError> for DHError {
    fn from(error: ProviderError) -> Self {
        Self::Provider(error)
    }
}

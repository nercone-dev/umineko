use core::fmt;

use umineko_helpers::provider::ProviderError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScryptError {
    Cost,
    Parameters,
    Length,
    Memory,
    Provider(ProviderError),
}

impl fmt::Display for ScryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl core::error::Error for ScryptError {}

impl From<ProviderError> for ScryptError {
    fn from(error: ProviderError) -> Self {
        Self::Provider(error)
    }
}

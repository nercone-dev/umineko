use core::fmt;

use umineko_helpers::provider::ProviderError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UDSError {
    Path,
    Type,
    PathInUse,
    NotFound,
    Permission,
    Refused,
    Limit,
    Closed,
    Ancillary,
    Transport,
    Provider(ProviderError),
    Timeout,
}

impl fmt::Display for UDSError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl core::error::Error for UDSError {}

impl From<ProviderError> for UDSError {
    fn from(error: ProviderError) -> Self {
        Self::Provider(error)
    }
}

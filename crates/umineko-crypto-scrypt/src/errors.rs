use core::fmt;

use umineko_helpers::provider::ProviderError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScryptError {
    Cost,
    Parameters,
    Length,
    Memory,
    Verification,
    Provider(ProviderError),
}

impl ScryptError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Cost => "invalid cost",
            Self::Parameters => "invalid parameters",
            Self::Length => "invalid length",
            Self::Memory => "memory exhausted",
            Self::Verification => "verification failed",
            Self::Provider(_) => "provider error",
        }
    }
}

impl fmt::Display for ScryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Provider(error) => write!(f, "provider error: {error}"),
            other => f.write_str(other.as_str()),
        }
    }
}

impl core::error::Error for ScryptError {}

impl From<ProviderError> for ScryptError {
    fn from(error: ProviderError) -> Self {
        match error {
            ProviderError::Verification => Self::Verification,
            other => Self::Provider(other),
        }
    }
}

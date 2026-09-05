use core::fmt;

use umineko_helpers::provider::ProviderError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HMACError {
    Length,
    Authentication,
    Provider(ProviderError),
}

impl HMACError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Length => "invalid length",
            Self::Authentication => "authentication failed",
            Self::Provider(_) => "provider error",
        }
    }
}

impl fmt::Display for HMACError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Provider(error) => write!(f, "provider error: {error}"),
            other => f.write_str(other.as_str()),
        }
    }
}

impl core::error::Error for HMACError {}

impl From<ProviderError> for HMACError {
    fn from(error: ProviderError) -> Self {
        Self::Provider(error)
    }
}

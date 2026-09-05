use core::fmt;

use umineko_helpers::provider::ProviderError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PBKDF2Error {
    Length,
    Iterations,
    Verification,
    Provider(ProviderError),
}

impl PBKDF2Error {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Length => "invalid length",
            Self::Iterations => "invalid iteration count",
            Self::Verification => "verification failed",
            Self::Provider(_) => "provider error",
        }
    }
}

impl fmt::Display for PBKDF2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Provider(error) => write!(f, "provider error: {error}"),
            other => f.write_str(other.as_str()),
        }
    }
}

impl core::error::Error for PBKDF2Error {}

impl From<ProviderError> for PBKDF2Error {
    fn from(error: ProviderError) -> Self {
        match error {
            ProviderError::Verification => Self::Verification,
            other => Self::Provider(other),
        }
    }
}

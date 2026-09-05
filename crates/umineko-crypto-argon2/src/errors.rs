use core::fmt;

use umineko_helpers::provider::ProviderError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Argon2Error {
    Variant,
    Parameters,
    Salt,
    Length,
    Memory,
    Verification,
    Provider(ProviderError),
}

impl Argon2Error {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Variant => "unknown variant",
            Self::Parameters => "invalid parameters",
            Self::Salt => "invalid salt",
            Self::Length => "invalid length",
            Self::Memory => "memory exhausted",
            Self::Verification => "verification failed",
            Self::Provider(_) => "provider error",
        }
    }
}

impl fmt::Display for Argon2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Provider(error) => write!(f, "provider error: {error}"),
            other => f.write_str(other.as_str()),
        }
    }
}

impl core::error::Error for Argon2Error {}

impl From<ProviderError> for Argon2Error {
    fn from(error: ProviderError) -> Self {
        match error {
            ProviderError::Verification => Self::Verification,
            other => Self::Provider(other),
        }
    }
}

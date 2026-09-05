use core::fmt;

use umineko_helpers::provider::ProviderError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SLHDSAError {
        Variant,
        Key,
        Encoding,
        Length,
        Verification,
        Seed,
        Provider(ProviderError),
}

impl SLHDSAError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Variant => "unknown variant",
            Self::Key => "invalid key",
            Self::Encoding => "invalid encoding",
            Self::Length => "invalid length",
            Self::Verification => "verification failed",
            Self::Seed => "invalid seed",
            Self::Provider(_) => "provider error",
        }
    }
}

impl fmt::Display for SLHDSAError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Provider(error) => write!(f, "provider error: {error}"),
            other => f.write_str(other.as_str()),
        }
    }
}

impl core::error::Error for SLHDSAError {}

impl From<ProviderError> for SLHDSAError {
    fn from(error: ProviderError) -> Self {
        match error {
            ProviderError::Verification => Self::Verification,
            other => Self::Provider(other),
        }
    }
}

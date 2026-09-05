use core::fmt;

use umineko_helpers::provider::ProviderError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HQCError {
        Variant,
        Key,
        Encoding,
        Length,
        Verification,
        Seed,
        Provider(ProviderError),
}

impl HQCError {
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

impl fmt::Display for HQCError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Provider(error) => write!(f, "provider error: {error}"),
            other => f.write_str(other.as_str()),
        }
    }
}

impl core::error::Error for HQCError {}

impl From<ProviderError> for HQCError {
    fn from(error: ProviderError) -> Self {
        match error {
            ProviderError::Verification => Self::Verification,
            other => Self::Provider(other),
        }
    }
}

use core::fmt;

use umineko_helpers::provider::ProviderError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RSAError {
        Key,
        Size,
        Encoding,
        Padding,
        Length,
        Verification,
        Seed,
        Provider(ProviderError),
}

impl RSAError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Key => "invalid key",
            Self::Size => "invalid modulus size",
            Self::Encoding => "invalid encoding",
            Self::Padding => "invalid padding",
            Self::Length => "invalid length",
            Self::Verification => "verification failed",
            Self::Seed => "invalid seed",
            Self::Provider(_) => "provider error",
        }
    }
}

impl fmt::Display for RSAError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Provider(error) => write!(f, "provider error: {error}"),
            other => f.write_str(other.as_str()),
        }
    }
}

impl core::error::Error for RSAError {}

impl From<ProviderError> for RSAError {
    fn from(error: ProviderError) -> Self {
        match error {
            ProviderError::Verification => Self::Verification,
            other => Self::Provider(other),
        }
    }
}

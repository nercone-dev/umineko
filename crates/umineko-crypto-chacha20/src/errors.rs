use core::fmt;

use umineko_helpers::provider::ProviderError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChaCha20Error {
        Key,
        Nonce,
        Length,
        Padding,
        Authentication,
        Variant,
        Provider(ProviderError),
}

impl ChaCha20Error {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Key => "invalid key",
            Self::Nonce => "invalid nonce",
            Self::Length => "invalid length",
            Self::Padding => "invalid padding",
            Self::Authentication => "authentication failed",
            Self::Variant => "unknown variant",
            Self::Provider(_) => "provider error",
        }
    }
}

impl fmt::Display for ChaCha20Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Provider(error) => write!(f, "provider error: {error}"),
            other => f.write_str(other.as_str()),
        }
    }
}

impl core::error::Error for ChaCha20Error {}

impl From<ProviderError> for ChaCha20Error {
    fn from(error: ProviderError) -> Self {
        match error {
            ProviderError::Authentication => Self::Authentication,
            other => Self::Provider(other),
        }
    }
}

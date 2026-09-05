use core::fmt;

use umineko_helpers::provider::ProviderError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Poly1305Error {
        Key,
        Nonce,
        Length,
        Padding,
        Authentication,
        Variant,
        Provider(ProviderError),
}

impl Poly1305Error {
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

impl fmt::Display for Poly1305Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Provider(error) => write!(f, "provider error: {error}"),
            other => f.write_str(other.as_str()),
        }
    }
}

impl core::error::Error for Poly1305Error {}

impl From<ProviderError> for Poly1305Error {
    fn from(error: ProviderError) -> Self {
        Self::Provider(error)
    }
}

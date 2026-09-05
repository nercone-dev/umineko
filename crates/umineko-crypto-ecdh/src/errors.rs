use core::fmt;

use umineko_helpers::provider::ProviderError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ECDHError {
        Curve,
        Key,
        Encoding,
        Point,
        SharedSecret,
        Seed,
        Provider(ProviderError),
}

impl ECDHError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Curve => "unknown curve",
            Self::Key => "invalid key",
            Self::Encoding => "invalid encoding",
            Self::Point => "invalid point",
            Self::SharedSecret => "invalid shared secret",
            Self::Seed => "invalid seed",
            Self::Provider(_) => "provider error",
        }
    }
}

impl fmt::Display for ECDHError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Provider(error) => write!(f, "provider error: {error}"),
            other => f.write_str(other.as_str()),
        }
    }
}

impl core::error::Error for ECDHError {}

impl From<ProviderError> for ECDHError {
    fn from(error: ProviderError) -> Self {
        Self::Provider(error)
    }
}

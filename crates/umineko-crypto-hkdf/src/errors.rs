use core::fmt;

use umineko_helpers::provider::ProviderError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HKDFError {
    Length,
    PseudorandomKey,
    Provider(ProviderError),
}

impl HKDFError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Length => "invalid length",
            Self::PseudorandomKey => "invalid pseudorandom key",
            Self::Provider(_) => "provider error",
        }
    }
}

impl fmt::Display for HKDFError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Provider(error) => write!(f, "provider error: {error}"),
            other => f.write_str(other.as_str()),
        }
    }
}

impl core::error::Error for HKDFError {}

impl From<ProviderError> for HKDFError {
    fn from(error: ProviderError) -> Self {
        Self::Provider(error)
    }
}

use core::fmt;

use umineko_helpers::provider::ProviderError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZstandardError {
    /// The stream does not follow the format.
    Format,
    /// The stream carries a checksum that does not match its content.
    Checksum,
    /// The output would grow past its limit.
    Limit,
    /// The stream ends inside a token.
    Truncated,
    /// A provider refused the work.
    Provider(ProviderError),
}

impl ZstandardError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Format => "malformed stream",
            Self::Checksum => "checksum mismatch",
            Self::Limit => "limit exceeded",
            Self::Truncated => "truncated stream",
            Self::Provider(_) => "provider error",
        }
    }
}

impl fmt::Display for ZstandardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Provider(error) => write!(f, "provider error: {error}"),
            other => f.write_str(other.as_str()),
        }
    }
}

impl core::error::Error for ZstandardError {}

impl From<ProviderError> for ZstandardError {
    fn from(error: ProviderError) -> Self {
        match error {
            ProviderError::Format => Self::Format,
            ProviderError::Truncated => Self::Truncated,
            ProviderError::Limit => Self::Limit,
            other => Self::Provider(other),
        }
    }
}

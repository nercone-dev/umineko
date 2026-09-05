use core::fmt;

use umineko_helpers::provider::ProviderError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LZMAError {
    /// The stream does not follow the format.
    Format,
    /// The stream carries a checksum that does not match its content.
    Checksum,
    /// The output would grow past its limit.
    Limit,
    /// The stream ends inside a token.
    Truncated,
    /// The stream carries properties this codec cannot follow.
    Properties,
    /// A provider refused the work.
    Provider(ProviderError),
}

impl LZMAError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Format => "malformed stream",
            Self::Checksum => "checksum mismatch",
            Self::Limit => "limit exceeded",
            Self::Truncated => "truncated stream",
            Self::Properties => "invalid properties",
            Self::Provider(_) => "provider error",
        }
    }
}

impl fmt::Display for LZMAError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Provider(error) => write!(f, "provider error: {error}"),
            other => f.write_str(other.as_str()),
        }
    }
}

impl core::error::Error for LZMAError {}

impl From<ProviderError> for LZMAError {
    fn from(error: ProviderError) -> Self {
        match error {
            ProviderError::Format => Self::Format,
            ProviderError::Truncated => Self::Truncated,
            ProviderError::Limit => Self::Limit,
            other => Self::Provider(other),
        }
    }
}

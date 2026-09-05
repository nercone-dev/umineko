use core::fmt;

use umineko_helpers::provider::ProviderError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GzipError {
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

impl GzipError {
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

impl fmt::Display for GzipError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Provider(error) => write!(f, "provider error: {error}"),
            other => f.write_str(other.as_str()),
        }
    }
}

impl core::error::Error for GzipError {}

impl From<umineko_codec_deflate::DeflateError> for GzipError {
    fn from(error: umineko_codec_deflate::DeflateError) -> Self {
        match error {
            umineko_codec_deflate::DeflateError::Truncated => Self::Truncated,
            umineko_codec_deflate::DeflateError::Limit => Self::Limit,
            umineko_codec_deflate::DeflateError::Checksum => Self::Checksum,
            umineko_codec_deflate::DeflateError::Provider(error) => Self::Provider(error),
            umineko_codec_deflate::DeflateError::Format => Self::Format,
        }
    }
}

impl From<ProviderError> for GzipError {
    fn from(error: ProviderError) -> Self {
        match error {
            ProviderError::Format => Self::Format,
            ProviderError::Truncated => Self::Truncated,
            ProviderError::Limit => Self::Limit,
            other => Self::Provider(other),
        }
    }
}

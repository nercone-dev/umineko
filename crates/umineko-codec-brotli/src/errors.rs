use core::fmt;

use umineko_helpers::provider::ProviderError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrotliError {
    /// The stream does not follow the format.
    Format,
    /// The stream carries a checksum that does not match its content.
    Checksum,
    /// The output would grow past its limit.
    Limit,
    /// The stream ends inside a token.
    Truncated,
    /// A provider was asked for work it does not do.
    Unsupported,
    /// A provider refused the work.
    Provider(ProviderError),
}

impl BrotliError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Format => "malformed stream",
            Self::Checksum => "checksum mismatch",
            Self::Limit => "limit exceeded",
            Self::Truncated => "truncated stream",
            Self::Unsupported => "unsupported request",
            Self::Provider(_) => "provider error",
        }
    }
}

impl fmt::Display for BrotliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Provider(error) => write!(f, "provider error: {error}"),
            other => f.write_str(other.as_str()),
        }
    }
}

impl core::error::Error for BrotliError {}

impl From<umineko_codec_huffman::HuffmanError> for BrotliError {
    fn from(error: umineko_codec_huffman::HuffmanError) -> Self {
        match error {
            umineko_codec_huffman::HuffmanError::Truncated => Self::Truncated,
            umineko_codec_huffman::HuffmanError::Limit => Self::Limit,
            _ => Self::Format,
        }
    }
}

impl From<ProviderError> for BrotliError {
    fn from(error: ProviderError) -> Self {
        match error {
            ProviderError::Unsupported => Self::Unsupported,
            ProviderError::Format => Self::Format,
            ProviderError::Truncated => Self::Truncated,
            ProviderError::Limit => Self::Limit,
            other => Self::Provider(other),
        }
    }
}

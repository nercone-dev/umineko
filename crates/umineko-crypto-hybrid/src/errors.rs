use core::fmt;

use umineko_crypto_ecdh::ECDHError;
use umineko_crypto_mlkem::MLKEMError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HybridKEXError {
    Variant,
    Length,
    ECDH(ECDHError),
    MLKEM(MLKEMError),
}

impl HybridKEXError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Variant => "unknown variant",
            Self::Length => "invalid length",
            Self::ECDH(_) => "curve error",
            Self::MLKEM(_) => "lattice error",
        }
    }
}

impl fmt::Display for HybridKEXError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ECDH(error) => write!(f, "curve error: {error}"),
            Self::MLKEM(error) => write!(f, "lattice error: {error}"),
            other => f.write_str(other.as_str()),
        }
    }
}

impl core::error::Error for HybridKEXError {}

impl From<ECDHError> for HybridKEXError {
    fn from(error: ECDHError) -> Self {
        Self::ECDH(error)
    }
}

impl From<MLKEMError> for HybridKEXError {
    fn from(error: MLKEMError) -> Self {
        Self::MLKEM(error)
    }
}

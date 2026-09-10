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

impl fmt::Display for HybridKEXError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
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

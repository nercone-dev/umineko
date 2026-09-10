use core::fmt;

use umineko_helpers::provider::ProviderError;
use umineko_crypto_gost::GOSTError;
use umineko_crypto_kdftree::KDFTreeError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GOSTR3410Error {
    Curve,
    Digest,
    Key,
    Encoding,
    Point,
    Verification,
    SharedSecret,
    Seed,
    GOST(GOSTError),
    KDFTree(KDFTreeError),
    Provider(ProviderError),
}

impl fmt::Display for GOSTR3410Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl core::error::Error for GOSTR3410Error {}

impl From<ProviderError> for GOSTR3410Error {
    fn from(error: ProviderError) -> Self {
        match error {
            ProviderError::Verification => Self::Verification,
            other => Self::Provider(other),
        }
    }
}

impl From<GOSTError> for GOSTR3410Error {
    fn from(error: GOSTError) -> Self {
        Self::GOST(error)
    }
}

impl From<KDFTreeError> for GOSTR3410Error {
    fn from(error: KDFTreeError) -> Self {
        Self::KDFTree(error)
    }
}

use alloc::vec::Vec;
use core::fmt;
use crate::errors::MLDSAError;

use umineko_helpers::provider::{SignatureProviderRequest, SignatureProviders};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MLDSA {
    V44,
    V65,
    V87,
}

impl MLDSA {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::V44 => "ML-DSA-44",
            Self::V65 => "ML-DSA-65",
            Self::V87 => "ML-DSA-87",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "ML-DSA-44" => Some(Self::V44),
            "ML-DSA-65" => Some(Self::V65),
            "ML-DSA-87" => Some(Self::V87),
            _ => None,
        }
    }

    pub fn public_key_size(&self) -> usize {
        todo!()
    }

    pub fn private_key_size(&self) -> usize {
        todo!()
    }

    pub fn signature_size(&self) -> usize {
        todo!()
    }

    pub fn seed_size(&self) -> usize {
        todo!()
    }
}

impl fmt::Display for MLDSA {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl MLDSA {
    pub fn request(&self) -> SignatureProviderRequest<'static> {
        SignatureProviderRequest::new(self.as_str())
    }

    pub fn generate(&self, seed: &[u8]) -> Result<(MLDSAPrivateKey, MLDSAPublicKey), MLDSAError> {
        match SignatureProviders::generate(&self.request().with_seed(seed))? {
            Some((private, public)) => Ok((MLDSAPrivateKey { variant: *self, key: private }, MLDSAPublicKey { variant: *self, key: public })),
            None => todo!(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MLDSAPrivateKey {
    variant: MLDSA,
    key: Vec<u8>,
}

impl MLDSAPrivateKey {
    pub fn decode(variant: MLDSA, data: &[u8]) -> Result<Self, MLDSAError> {
        todo!()
    }

    pub fn encode(&self) -> Vec<u8> {
        self.key.clone()
    }

    pub fn variant(&self) -> MLDSA {
        self.variant
    }

    pub fn public_key(&self) -> MLDSAPublicKey {
        let request = self.variant.request();
        match SignatureProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.public_key(&request, &self.key)) {
            Some(key) => MLDSAPublicKey { variant: self.variant, key },
            None => todo!(),
        }
    }

    pub fn sign(&self, message: &[u8], context: &[u8]) -> Result<MLDSASignature, MLDSAError> {
        match SignatureProviders::sign(&self.variant.request().with_context(context), &self.key, message)? {
            Some(signature) => Ok(MLDSASignature { variant: self.variant, signature }),
            None => todo!(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MLDSAPublicKey {
    variant: MLDSA,
    key: Vec<u8>,
}

impl MLDSAPublicKey {
    pub fn decode(variant: MLDSA, data: &[u8]) -> Result<Self, MLDSAError> {
        todo!()
    }

    pub fn encode(&self) -> Vec<u8> {
        self.key.clone()
    }

    pub fn variant(&self) -> MLDSA {
        self.variant
    }

    pub fn verify(&self, message: &[u8], signature: &MLDSASignature, context: &[u8]) -> Result<(), MLDSAError> {
        match SignatureProviders::verify(&self.variant.request().with_context(context), &self.key, message, &signature.signature)? {
            Some(()) => Ok(()),
            None => todo!(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MLDSASignature {
    variant: MLDSA,
    signature: Vec<u8>,
}

impl MLDSASignature {
    pub fn decode(variant: MLDSA, data: &[u8]) -> Result<Self, MLDSAError> {
        todo!()
    }

    pub fn encode(&self) -> Vec<u8> {
        self.signature.clone()
    }

    pub fn variant(&self) -> MLDSA {
        self.variant
    }
}

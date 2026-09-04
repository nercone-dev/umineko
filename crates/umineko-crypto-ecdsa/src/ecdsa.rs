use alloc::vec::Vec;
use core::fmt;
use crate::errors::ECDSAError;

use umineko_helpers::provider::{SignatureProviderRequest, SignatureProviders};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ECDSA {
    SECP256R1,
    SECP384R1,
    SECP521R1,
    SECP256K1,
}

impl ECDSA {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SECP256R1 => "secp256r1",
            Self::SECP384R1 => "secp384r1",
            Self::SECP521R1 => "secp521r1",
            Self::SECP256K1 => "secp256k1",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "secp256r1" => Some(Self::SECP256R1),
            "secp384r1" => Some(Self::SECP384R1),
            "secp521r1" => Some(Self::SECP521R1),
            "secp256k1" => Some(Self::SECP256K1),
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

impl fmt::Display for ECDSA {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl ECDSA {
    pub fn request(&self) -> SignatureProviderRequest<'static> {
        SignatureProviderRequest::new(self.as_str())
    }

    pub fn generate(&self, seed: &[u8]) -> Result<(ECDSAPrivateKey, ECDSAPublicKey), ECDSAError> {
        match SignatureProviders::generate(&self.request().with_seed(seed))? {
            Some((private, public)) => Ok((ECDSAPrivateKey { variant: *self, key: private }, ECDSAPublicKey { variant: *self, key: public })),
            None => todo!(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ECDSAPrivateKey {
    variant: ECDSA,
    key: Vec<u8>,
}

impl ECDSAPrivateKey {
    pub fn decode(variant: ECDSA, data: &[u8]) -> Result<Self, ECDSAError> {
        todo!()
    }

    pub fn encode(&self) -> Vec<u8> {
        self.key.clone()
    }

    pub fn variant(&self) -> ECDSA {
        self.variant
    }

    pub fn public_key(&self) -> ECDSAPublicKey {
        let request = self.variant.request();
        match SignatureProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.public_key(&request, &self.key)) {
            Some(key) => ECDSAPublicKey { variant: self.variant, key },
            None => todo!(),
        }
    }

    pub fn sign(&self, message: &[u8]) -> Result<ECDSASignature, ECDSAError> {
        match SignatureProviders::sign(&self.variant.request(), &self.key, message)? {
            Some(signature) => Ok(ECDSASignature { variant: self.variant, signature }),
            None => todo!(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ECDSAPublicKey {
    variant: ECDSA,
    key: Vec<u8>,
}

impl ECDSAPublicKey {
    pub fn decode(variant: ECDSA, data: &[u8]) -> Result<Self, ECDSAError> {
        todo!()
    }

    pub fn encode(&self) -> Vec<u8> {
        self.key.clone()
    }

    pub fn variant(&self) -> ECDSA {
        self.variant
    }

    pub fn verify(&self, message: &[u8], signature: &ECDSASignature) -> Result<(), ECDSAError> {
        match SignatureProviders::verify(&self.variant.request(), &self.key, message, &signature.signature)? {
            Some(()) => Ok(()),
            None => todo!(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ECDSASignature {
    variant: ECDSA,
    signature: Vec<u8>,
}

impl ECDSASignature {
    pub fn decode(variant: ECDSA, data: &[u8]) -> Result<Self, ECDSAError> {
        todo!()
    }

    pub fn encode(&self) -> Vec<u8> {
        self.signature.clone()
    }

    pub fn variant(&self) -> ECDSA {
        self.variant
    }
}

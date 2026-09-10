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
    SECT163K1,
    SECT163R1,
    SECT163R2,
    SECT193R1,
    SECT193R2,
    SECT233K1,
    SECT233R1,
    SECT239K1,
    SECT283K1,
    SECT283R1,
    SECT409K1,
    SECT409R1,
    SECT571K1,
    SECT571R1,
    SECP160K1,
    SECP160R1,
    SECP160R2,
    SECP192K1,
    SECP192R1,
    SECP224K1,
    SECP224R1,
    BRAINPOOLP256R1,
    BRAINPOOLP384R1,
    BRAINPOOLP512R1,
}

impl ECDSA {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SECP256R1 => "secp256r1",
            Self::SECP384R1 => "secp384r1",
            Self::SECP521R1 => "secp521r1",
            Self::SECP256K1 => "secp256k1",
            Self::SECT163K1 => "sect163k1",
            Self::SECT163R1 => "sect163r1",
            Self::SECT163R2 => "sect163r2",
            Self::SECT193R1 => "sect193r1",
            Self::SECT193R2 => "sect193r2",
            Self::SECT233K1 => "sect233k1",
            Self::SECT233R1 => "sect233r1",
            Self::SECT239K1 => "sect239k1",
            Self::SECT283K1 => "sect283k1",
            Self::SECT283R1 => "sect283r1",
            Self::SECT409K1 => "sect409k1",
            Self::SECT409R1 => "sect409r1",
            Self::SECT571K1 => "sect571k1",
            Self::SECT571R1 => "sect571r1",
            Self::SECP160K1 => "secp160k1",
            Self::SECP160R1 => "secp160r1",
            Self::SECP160R2 => "secp160r2",
            Self::SECP192K1 => "secp192k1",
            Self::SECP192R1 => "secp192r1",
            Self::SECP224K1 => "secp224k1",
            Self::SECP224R1 => "secp224r1",
            Self::BRAINPOOLP256R1 => "brainpoolP256r1",
            Self::BRAINPOOLP384R1 => "brainpoolP384r1",
            Self::BRAINPOOLP512R1 => "brainpoolP512r1",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "secp256r1" => Some(Self::SECP256R1),
            "secp384r1" => Some(Self::SECP384R1),
            "secp521r1" => Some(Self::SECP521R1),
            "secp256k1" => Some(Self::SECP256K1),
            "sect163k1" => Some(Self::SECT163K1),
            "sect163r1" => Some(Self::SECT163R1),
            "sect163r2" => Some(Self::SECT163R2),
            "sect193r1" => Some(Self::SECT193R1),
            "sect193r2" => Some(Self::SECT193R2),
            "sect233k1" => Some(Self::SECT233K1),
            "sect233r1" => Some(Self::SECT233R1),
            "sect239k1" => Some(Self::SECT239K1),
            "sect283k1" => Some(Self::SECT283K1),
            "sect283r1" => Some(Self::SECT283R1),
            "sect409k1" => Some(Self::SECT409K1),
            "sect409r1" => Some(Self::SECT409R1),
            "sect571k1" => Some(Self::SECT571K1),
            "sect571r1" => Some(Self::SECT571R1),
            "secp160k1" => Some(Self::SECP160K1),
            "secp160r1" => Some(Self::SECP160R1),
            "secp160r2" => Some(Self::SECP160R2),
            "secp192k1" => Some(Self::SECP192K1),
            "secp192r1" => Some(Self::SECP192R1),
            "secp224k1" => Some(Self::SECP224K1),
            "secp224r1" => Some(Self::SECP224R1),
            "brainpoolP256r1" => Some(Self::BRAINPOOLP256R1),
            "brainpoolP384r1" => Some(Self::BRAINPOOLP384R1),
            "brainpoolP512r1" => Some(Self::BRAINPOOLP512R1),
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

    pub fn sign(&self, digest: &[u8]) -> Result<ECDSASignature, ECDSAError> {
        match SignatureProviders::sign(&self.variant.request(), &self.key, digest)? {
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

    pub fn verify(&self, digest: &[u8], signature: &ECDSASignature) -> Result<(), ECDSAError> {
        match SignatureProviders::verify(&self.variant.request(), &self.key, digest, &signature.signature)? {
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

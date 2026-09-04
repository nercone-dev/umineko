use alloc::vec::Vec;
use core::fmt;
use crate::errors::HQCError;

use umineko_helpers::provider::{ExchangeProviderRequest, ExchangeProviders};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HQC {
    V128,
    V192,
    V256,
}

impl HQC {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::V128 => "HQC-128",
            Self::V192 => "HQC-192",
            Self::V256 => "HQC-256",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "HQC-128" => Some(Self::V128),
            "HQC-192" => Some(Self::V192),
            "HQC-256" => Some(Self::V256),
            _ => None,
        }
    }

    pub fn public_key_size(&self) -> usize {
        todo!()
    }

    pub fn private_key_size(&self) -> usize {
        todo!()
    }

    pub fn ciphertext_size(&self) -> usize {
        todo!()
    }

    pub fn shared_secret_size(&self) -> usize {
        todo!()
    }

    pub fn seed_size(&self) -> usize {
        todo!()
    }
}

impl fmt::Display for HQC {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl HQC {
    pub fn request(&self) -> ExchangeProviderRequest<'static> {
        ExchangeProviderRequest::new(self.as_str())
    }

    pub fn generate(&self, seed: &[u8]) -> Result<(HQCPrivateKey, HQCPublicKey), HQCError> {
        match ExchangeProviders::generate(&self.request().with_seed(seed))? {
            Some((private, public)) => Ok((HQCPrivateKey { variant: *self, key: private }, HQCPublicKey { variant: *self, key: public })),
            None => todo!(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HQCPrivateKey {
    variant: HQC,
    key: Vec<u8>,
}

impl HQCPrivateKey {
    pub fn decode(variant: HQC, data: &[u8]) -> Result<Self, HQCError> {
        todo!()
    }

    pub fn encode(&self) -> Vec<u8> {
        self.key.clone()
    }

    pub fn variant(&self) -> HQC {
        self.variant
    }

    pub fn public_key(&self) -> HQCPublicKey {
        let request = self.variant.request();
        match ExchangeProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.public_key(&request, &self.key)) {
            Some(key) => HQCPublicKey { variant: self.variant, key },
            None => todo!(),
        }
    }

    pub fn decapsulate(&self, ciphertext: &HQCCiphertext) -> Result<HQCSharedSecret, HQCError> {
        match ExchangeProviders::decapsulate(&self.variant.request(), &self.key, &ciphertext.ciphertext)? {
            Some(secret) => Ok(HQCSharedSecret { secret }),
            None => todo!(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HQCPublicKey {
    variant: HQC,
    key: Vec<u8>,
}

impl HQCPublicKey {
    pub fn decode(variant: HQC, data: &[u8]) -> Result<Self, HQCError> {
        todo!()
    }

    pub fn encode(&self) -> Vec<u8> {
        self.key.clone()
    }

    pub fn variant(&self) -> HQC {
        self.variant
    }
    pub fn encapsulate(&self, seed: &[u8]) -> Result<(HQCCiphertext, HQCSharedSecret), HQCError> {
        match ExchangeProviders::encapsulate(&self.variant.request().with_seed(seed), &self.key)? {
            Some((ciphertext, secret)) => Ok((HQCCiphertext { variant: self.variant, ciphertext }, HQCSharedSecret { secret })),
            None => todo!(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HQCCiphertext {
    variant: HQC,
    ciphertext: Vec<u8>,
}

impl HQCCiphertext {
    pub fn decode(variant: HQC, data: &[u8]) -> Result<Self, HQCError> {
        todo!()
    }

    pub fn encode(&self) -> Vec<u8> {
        self.ciphertext.clone()
    }

    pub fn variant(&self) -> HQC {
        self.variant
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HQCSharedSecret {
    secret: Vec<u8>,
}

impl HQCSharedSecret {
    pub fn as_slice(&self) -> &[u8] {
        &self.secret
    }

    pub fn len(&self) -> usize {
        self.secret.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

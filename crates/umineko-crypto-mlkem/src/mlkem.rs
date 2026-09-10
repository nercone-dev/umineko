use alloc::vec::Vec;
use core::fmt;
use crate::errors::MLKEMError;

use umineko_helpers::provider::{ExchangeProviderRequest, ExchangeProviders};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MLKEM {
    V512,
    V768,
    V1024,
}

impl MLKEM {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::V512 => "ML-KEM-512",
            Self::V768 => "ML-KEM-768",
            Self::V1024 => "ML-KEM-1024",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "ML-KEM-512" => Some(Self::V512),
            "ML-KEM-768" => Some(Self::V768),
            "ML-KEM-1024" => Some(Self::V1024),
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

impl fmt::Display for MLKEM {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl MLKEM {
    pub fn request(&self) -> ExchangeProviderRequest<'static> {
        ExchangeProviderRequest::new(self.as_str())
    }

    pub fn generate(&self, seed: &[u8]) -> Result<(MLKEMPrivateKey, MLKEMPublicKey), MLKEMError> {
        match ExchangeProviders::generate(&self.request().with_seed(seed))? {
            Some((private, public)) => Ok((MLKEMPrivateKey { variant: *self, key: private }, MLKEMPublicKey { variant: *self, key: public })),
            None => todo!(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MLKEMPrivateKey {
    variant: MLKEM,
    key: Vec<u8>,
}

impl MLKEMPrivateKey {
    pub fn decode(variant: MLKEM, data: &[u8]) -> Result<Self, MLKEMError> {
        todo!()
    }

    pub fn encode(&self) -> Vec<u8> {
        self.key.clone()
    }

    pub fn variant(&self) -> MLKEM {
        self.variant
    }

    pub fn public_key(&self) -> MLKEMPublicKey {
        let request = self.variant.request();
        match ExchangeProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.public_key(&request, &self.key)) {
            Some(key) => MLKEMPublicKey { variant: self.variant, key },
            None => todo!(),
        }
    }

    pub fn decapsulate(&self, ciphertext: &MLKEMCiphertext) -> Result<MLKEMSharedSecret, MLKEMError> {
        match ExchangeProviders::decapsulate(&self.variant.request(), &self.key, &ciphertext.ciphertext)? {
            Some(secret) => Ok(MLKEMSharedSecret { secret }),
            None => todo!(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MLKEMPublicKey {
    variant: MLKEM,
    key: Vec<u8>,
}

impl MLKEMPublicKey {
    pub fn decode(variant: MLKEM, data: &[u8]) -> Result<Self, MLKEMError> {
        todo!()
    }

    pub fn encode(&self) -> Vec<u8> {
        self.key.clone()
    }

    pub fn variant(&self) -> MLKEM {
        self.variant
    }
    pub fn encapsulate(&self, seed: &[u8]) -> Result<(MLKEMCiphertext, MLKEMSharedSecret), MLKEMError> {
        match ExchangeProviders::encapsulate(&self.variant.request().with_seed(seed), &self.key)? {
            Some((ciphertext, secret)) => Ok((MLKEMCiphertext { variant: self.variant, ciphertext }, MLKEMSharedSecret { secret })),
            None => todo!(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MLKEMCiphertext {
    variant: MLKEM,
    ciphertext: Vec<u8>,
}

impl MLKEMCiphertext {
    pub fn decode(variant: MLKEM, data: &[u8]) -> Result<Self, MLKEMError> {
        todo!()
    }

    pub fn encode(&self) -> Vec<u8> {
        self.ciphertext.clone()
    }

    pub fn variant(&self) -> MLKEM {
        self.variant
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MLKEMSharedSecret {
    secret: Vec<u8>,
}

impl MLKEMSharedSecret {
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

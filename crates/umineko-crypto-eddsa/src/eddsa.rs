use alloc::vec::Vec;
use core::fmt;
use crate::errors::EdDSAError;

use umineko_helpers::provider::{SignatureProviderRequest, SignatureProviders};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EdDSA {
    Ed25519,
    Ed448,
}

impl EdDSA {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ed25519 => "Ed25519",
            Self::Ed448 => "Ed448",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "Ed25519" => Some(Self::Ed25519),
            "Ed448" => Some(Self::Ed448),
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

impl fmt::Display for EdDSA {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl EdDSA {
    pub fn request(&self) -> SignatureProviderRequest<'static> {
        SignatureProviderRequest::new(self.as_str())
    }

    pub fn generate(&self, seed: &[u8]) -> Result<(EdDSAPrivateKey, EdDSAPublicKey), EdDSAError> {
        match SignatureProviders::generate(&self.request().with_seed(seed))? {
            Some((private, public)) => Ok((EdDSAPrivateKey { variant: *self, key: private }, EdDSAPublicKey { variant: *self, key: public })),
            None => todo!(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdDSAPrivateKey {
    variant: EdDSA,
    key: Vec<u8>,
}

impl EdDSAPrivateKey {
    pub fn decode(variant: EdDSA, data: &[u8]) -> Result<Self, EdDSAError> {
        todo!()
    }

    pub fn encode(&self) -> Vec<u8> {
        self.key.clone()
    }

    pub fn variant(&self) -> EdDSA {
        self.variant
    }

    pub fn public_key(&self) -> EdDSAPublicKey {
        let request = self.variant.request();
        match SignatureProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.public_key(&request, &self.key)) {
            Some(key) => EdDSAPublicKey { variant: self.variant, key },
            None => todo!(),
        }
    }

    pub fn sign(&self, message: &[u8], context: &[u8]) -> Result<EdDSASignature, EdDSAError> {
        match SignatureProviders::sign(&self.variant.request().with_context(context), &self.key, message)? {
            Some(signature) => Ok(EdDSASignature { variant: self.variant, signature }),
            None => todo!(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdDSAPublicKey {
    variant: EdDSA,
    key: Vec<u8>,
}

impl EdDSAPublicKey {
    pub fn decode(variant: EdDSA, data: &[u8]) -> Result<Self, EdDSAError> {
        todo!()
    }

    pub fn encode(&self) -> Vec<u8> {
        self.key.clone()
    }

    pub fn variant(&self) -> EdDSA {
        self.variant
    }

    pub fn verify(&self, message: &[u8], signature: &EdDSASignature, context: &[u8]) -> Result<(), EdDSAError> {
        match SignatureProviders::verify(&self.variant.request().with_context(context), &self.key, message, &signature.signature)? {
            Some(()) => Ok(()),
            None => todo!(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdDSASignature {
    variant: EdDSA,
    signature: Vec<u8>,
}

impl EdDSASignature {
    pub fn decode(variant: EdDSA, data: &[u8]) -> Result<Self, EdDSAError> {
        todo!()
    }

    pub fn encode(&self) -> Vec<u8> {
        self.signature.clone()
    }

    pub fn variant(&self) -> EdDSA {
        self.variant
    }
}

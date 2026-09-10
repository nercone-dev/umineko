use alloc::vec::Vec;
use core::fmt;
use crate::errors::DSAError;

use umineko_helpers::provider::{SignatureProviderRequest, SignatureProviders};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DSA {
    V1024_160,
    V2048_224,
    V2048_256,
    V3072_256,
}

impl DSA {
    pub const NAME: &'static str = "DSA";

    pub fn bits(&self) -> usize {
        match self {
            Self::V1024_160 => 1024,
            Self::V2048_224 => 2048,
            Self::V2048_256 => 2048,
            Self::V3072_256 => 3072,
        }
    }

    pub fn order_bits(&self) -> usize {
        match self {
            Self::V1024_160 => 160,
            Self::V2048_224 => 224,
            Self::V2048_256 => 256,
            Self::V3072_256 => 256,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::V1024_160 => "DSA-1024-160",
            Self::V2048_224 => "DSA-2048-224",
            Self::V2048_256 => "DSA-2048-256",
            Self::V3072_256 => "DSA-3072-256",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "DSA-1024-160" => Some(Self::V1024_160),
            "DSA-2048-224" => Some(Self::V2048_224),
            "DSA-2048-256" => Some(Self::V2048_256),
            "DSA-3072-256" => Some(Self::V3072_256),
            _ => None,
        }
    }

    pub fn request(&self) -> SignatureProviderRequest<'static> {
        SignatureProviderRequest::new(self.as_str())
    }

    pub fn generate(&self, seed: &[u8]) -> Result<(DSAPrivateKey, DSAPublicKey), DSAError> {
        match SignatureProviders::generate(&self.request().with_seed(seed))? {
            Some((private, public)) => Ok((DSAPrivateKey::decode(&private)?, DSAPublicKey::decode(&public)?)),
            None => todo!(),
        }
    }
}

impl fmt::Display for DSA {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DSAPrivateKey {
    prime: Vec<u8>,
    subprime: Vec<u8>,
    base: Vec<u8>,
    private: Vec<u8>,
    public: Vec<u8>,
}

impl DSAPrivateKey {
    pub fn decode(data: &[u8]) -> Result<Self, DSAError> {
        todo!()
    }

    pub fn encode(&self) -> Vec<u8> {
        todo!()
    }

    pub fn public_key(&self) -> DSAPublicKey {
        todo!()
    }

    pub fn bits(&self) -> usize {
        todo!()
    }

    pub fn sign(&self, digest: &[u8]) -> Result<DSASignature, DSAError> {
        match SignatureProviders::sign(&SignatureProviderRequest::new(DSA::NAME), &self.encode(), digest)? {
            Some(signature) => Ok(DSASignature { signature }),
            None => todo!(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DSAPublicKey {
    prime: Vec<u8>,
    subprime: Vec<u8>,
    base: Vec<u8>,
    public: Vec<u8>,
}

impl DSAPublicKey {
    pub fn decode(data: &[u8]) -> Result<Self, DSAError> {
        todo!()
    }

    pub fn encode(&self) -> Vec<u8> {
        todo!()
    }

    pub fn bits(&self) -> usize {
        todo!()
    }

    pub fn verify(&self, digest: &[u8], signature: &DSASignature) -> Result<(), DSAError> {
        match SignatureProviders::verify(&SignatureProviderRequest::new(DSA::NAME), &self.encode(), digest, &signature.signature)? {
            Some(()) => Ok(()),
            None => todo!(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DSASignature {
    signature: Vec<u8>,
}

impl DSASignature {
    pub fn decode(data: &[u8]) -> Result<Self, DSAError> {
        Ok(Self { signature: data.to_vec() })
    }

    pub fn encode(&self) -> Vec<u8> {
        self.signature.clone()
    }
}

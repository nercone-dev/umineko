use alloc::vec::Vec;
use core::fmt;
use crate::errors::SLHDSAError;

use umineko_helpers::provider::{SignatureProviderRequest, SignatureProviders};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SLHDSA {
    SHA2_128S,
    SHA2_128F,
    SHA2_192S,
    SHA2_192F,
    SHA2_256S,
    SHA2_256F,
    SHAKE_128S,
    SHAKE_128F,
    SHAKE_192S,
    SHAKE_192F,
    SHAKE_256S,
    SHAKE_256F,
}

impl SLHDSA {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SHA2_128S => "SLH-DSA-SHA2-128s",
            Self::SHA2_128F => "SLH-DSA-SHA2-128f",
            Self::SHA2_192S => "SLH-DSA-SHA2-192s",
            Self::SHA2_192F => "SLH-DSA-SHA2-192f",
            Self::SHA2_256S => "SLH-DSA-SHA2-256s",
            Self::SHA2_256F => "SLH-DSA-SHA2-256f",
            Self::SHAKE_128S => "SLH-DSA-SHAKE-128s",
            Self::SHAKE_128F => "SLH-DSA-SHAKE-128f",
            Self::SHAKE_192S => "SLH-DSA-SHAKE-192s",
            Self::SHAKE_192F => "SLH-DSA-SHAKE-192f",
            Self::SHAKE_256S => "SLH-DSA-SHAKE-256s",
            Self::SHAKE_256F => "SLH-DSA-SHAKE-256f",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "SLH-DSA-SHA2-128s" => Some(Self::SHA2_128S),
            "SLH-DSA-SHA2-128f" => Some(Self::SHA2_128F),
            "SLH-DSA-SHA2-192s" => Some(Self::SHA2_192S),
            "SLH-DSA-SHA2-192f" => Some(Self::SHA2_192F),
            "SLH-DSA-SHA2-256s" => Some(Self::SHA2_256S),
            "SLH-DSA-SHA2-256f" => Some(Self::SHA2_256F),
            "SLH-DSA-SHAKE-128s" => Some(Self::SHAKE_128S),
            "SLH-DSA-SHAKE-128f" => Some(Self::SHAKE_128F),
            "SLH-DSA-SHAKE-192s" => Some(Self::SHAKE_192S),
            "SLH-DSA-SHAKE-192f" => Some(Self::SHAKE_192F),
            "SLH-DSA-SHAKE-256s" => Some(Self::SHAKE_256S),
            "SLH-DSA-SHAKE-256f" => Some(Self::SHAKE_256F),
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

impl fmt::Display for SLHDSA {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl SLHDSA {
    pub fn request(&self) -> SignatureProviderRequest<'static> {
        SignatureProviderRequest::new(self.as_str())
    }

    pub fn generate(&self, seed: &[u8]) -> Result<(SLHDSAPrivateKey, SLHDSAPublicKey), SLHDSAError> {
        match SignatureProviders::generate(&self.request().with_seed(seed))? {
            Some((private, public)) => Ok((SLHDSAPrivateKey { variant: *self, key: private }, SLHDSAPublicKey { variant: *self, key: public })),
            None => todo!(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SLHDSAPrivateKey {
    variant: SLHDSA,
    key: Vec<u8>,
}

impl SLHDSAPrivateKey {
    pub fn decode(variant: SLHDSA, data: &[u8]) -> Result<Self, SLHDSAError> {
        todo!()
    }

    pub fn encode(&self) -> Vec<u8> {
        self.key.clone()
    }

    pub fn variant(&self) -> SLHDSA {
        self.variant
    }

    pub fn public_key(&self) -> SLHDSAPublicKey {
        let request = self.variant.request();
        match SignatureProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.public_key(&request, &self.key)) {
            Some(key) => SLHDSAPublicKey { variant: self.variant, key },
            None => todo!(),
        }
    }

    pub fn sign(&self, message: &[u8], context: &[u8]) -> Result<SLHDSASignature, SLHDSAError> {
        match SignatureProviders::sign(&self.variant.request().with_context(context), &self.key, message)? {
            Some(signature) => Ok(SLHDSASignature { variant: self.variant, signature }),
            None => todo!(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SLHDSAPublicKey {
    variant: SLHDSA,
    key: Vec<u8>,
}

impl SLHDSAPublicKey {
    pub fn decode(variant: SLHDSA, data: &[u8]) -> Result<Self, SLHDSAError> {
        todo!()
    }

    pub fn encode(&self) -> Vec<u8> {
        self.key.clone()
    }

    pub fn variant(&self) -> SLHDSA {
        self.variant
    }

    pub fn verify(&self, message: &[u8], signature: &SLHDSASignature, context: &[u8]) -> Result<(), SLHDSAError> {
        match SignatureProviders::verify(&self.variant.request().with_context(context), &self.key, message, &signature.signature)? {
            Some(()) => Ok(()),
            None => todo!(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SLHDSASignature {
    variant: SLHDSA,
    signature: Vec<u8>,
}

impl SLHDSASignature {
    pub fn decode(variant: SLHDSA, data: &[u8]) -> Result<Self, SLHDSAError> {
        todo!()
    }

    pub fn encode(&self) -> Vec<u8> {
        self.signature.clone()
    }

    pub fn variant(&self) -> SLHDSA {
        self.variant
    }
}

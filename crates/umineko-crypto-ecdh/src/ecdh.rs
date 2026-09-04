use alloc::vec::Vec;
use core::fmt;
use crate::errors::ECDHError;

use umineko_helpers::provider::{ExchangeProviderRequest, ExchangeProviders};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ECDH {
    X25519,
    X448,
    SECP256R1,
    SECP384R1,
    SECP521R1,
}

impl ECDH {
    pub fn public_key_size(&self) -> usize {
        todo!()
    }

    pub fn private_key_size(&self) -> usize {
        todo!()
    }

    pub fn shared_secret_size(&self) -> usize {
        todo!()
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::X25519 => "X25519",
            Self::X448 => "X448",
            Self::SECP256R1 => "secp256r1",
            Self::SECP384R1 => "secp384r1",
            Self::SECP521R1 => "secp521r1",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "X25519" => Some(Self::X25519),
            "X448" => Some(Self::X448),
            "secp256r1" => Some(Self::SECP256R1),
            "secp384r1" => Some(Self::SECP384R1),
            "secp521r1" => Some(Self::SECP521R1),
            _ => None,
        }
    }

    pub fn request(&self) -> ExchangeProviderRequest<'static> {
        ExchangeProviderRequest::new(self.as_str())
    }

    pub fn generate(&self, seed: &[u8]) -> Result<(ECDHPrivateKey, ECDHPublicKey), ECDHError> {
        match ExchangeProviders::generate(&self.request().with_seed(seed))? {
            Some((private, public)) => Ok((ECDHPrivateKey { curve: *self, key: private }, ECDHPublicKey { curve: *self, key: public })),
            None => todo!(),
        }
    }
}

impl fmt::Display for ECDH {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ECDHPrivateKey {
    curve: ECDH,
    key: Vec<u8>,
}

impl ECDHPrivateKey {
    pub fn decode(curve: ECDH, data: &[u8]) -> Result<Self, ECDHError> {
        todo!()
    }

    pub fn encode(&self) -> Vec<u8> {
        self.key.clone()
    }

    pub fn curve(&self) -> ECDH {
        self.curve
    }

    pub fn public_key(&self) -> ECDHPublicKey {
        let request = self.curve.request();
        match ExchangeProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.public_key(&request, &self.key)) {
            Some(key) => ECDHPublicKey { curve: self.curve, key },
            None => todo!(),
        }
    }

    pub fn exchange(&self, peer: &ECDHPublicKey) -> Result<ECDHSharedSecret, ECDHError> {
        match ExchangeProviders::exchange(&self.curve.request(), &self.key, &peer.key)? {
            Some(secret) => Ok(ECDHSharedSecret { secret }),
            None => todo!(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ECDHPublicKey {
    curve: ECDH,
    key: Vec<u8>,
}

impl ECDHPublicKey {
    pub fn decode(curve: ECDH, data: &[u8]) -> Result<Self, ECDHError> {
        todo!()
    }

    pub fn encode(&self) -> Vec<u8> {
        self.key.clone()
    }

    pub fn curve(&self) -> ECDH {
        self.curve
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ECDHSharedSecret {
    secret: Vec<u8>,
}

impl ECDHSharedSecret {
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

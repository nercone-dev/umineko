use alloc::vec::Vec;
use crate::errors::SM2Error;

use umineko_helpers::provider::{SignatureProviderRequest, SignatureProviders};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct SM2;

impl SM2 {
    pub const NAME: &'static str = "SM2";
    pub const DEFAULT_IDENTITY: &'static [u8] = b"1234567812345678";
    pub const PUBLIC_KEY_SIZE: usize = 65;
    pub const PRIVATE_KEY_SIZE: usize = 32;

    pub fn request(identity: &[u8]) -> SignatureProviderRequest<'_> {
        SignatureProviderRequest::new(Self::NAME).with_context(identity)
    }

    pub fn generate(seed: &[u8]) -> Result<(SM2PrivateKey, SM2PublicKey), SM2Error> {
        match SignatureProviders::generate(&SignatureProviderRequest::new(Self::NAME).with_seed(seed))? {
            Some((private, public)) => Ok((SM2PrivateKey { key: private }, SM2PublicKey { key: public })),
            None => todo!(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SM2PrivateKey {
    key: Vec<u8>,
}

impl SM2PrivateKey {
    pub fn decode(data: &[u8]) -> Result<Self, SM2Error> {
        todo!()
    }

    pub fn encode(&self) -> Vec<u8> {
        self.key.clone()
    }

    pub fn public_key(&self) -> SM2PublicKey {
        let request = SignatureProviderRequest::new(SM2::NAME);
        match SignatureProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.public_key(&request, &self.key)) {
            Some(key) => SM2PublicKey { key },
            None => todo!(),
        }
    }

    pub fn sign(&self, message: &[u8], identity: &[u8]) -> Result<SM2Signature, SM2Error> {
        match SignatureProviders::sign(&SM2::request(identity), &self.key, message)? {
            Some(signature) => Ok(SM2Signature { signature }),
            None => todo!(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SM2PublicKey {
    key: Vec<u8>,
}

impl SM2PublicKey {
    pub fn decode(data: &[u8]) -> Result<Self, SM2Error> {
        todo!()
    }

    pub fn encode(&self) -> Vec<u8> {
        self.key.clone()
    }

    pub fn verify(&self, message: &[u8], signature: &SM2Signature, identity: &[u8]) -> Result<(), SM2Error> {
        match SignatureProviders::verify(&SM2::request(identity), &self.key, message, &signature.signature)? {
            Some(()) => Ok(()),
            None => todo!(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SM2Signature {
    signature: Vec<u8>,
}

impl SM2Signature {
    pub fn decode(data: &[u8]) -> Result<Self, SM2Error> {
        todo!()
    }

    pub fn encode(&self) -> Vec<u8> {
        self.signature.clone()
    }
}

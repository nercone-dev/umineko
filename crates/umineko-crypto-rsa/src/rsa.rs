use alloc::vec::Vec;
use crate::errors::RSAError;

use umineko_helpers::provider::{CipherProviderRequest, CipherProviders, SignatureProviderRequest, SignatureProviders};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RSAPadding {
    PKCS1V15,
    OAEP,
    PSS,
}

impl RSAPadding {
        pub fn encryption(&self) -> bool {
        matches!(self, Self::PKCS1V15 | Self::OAEP)
    }

        pub fn signature(&self) -> bool {
        matches!(self, Self::PKCS1V15 | Self::PSS)
    }

        pub fn maximum_length(&self, modulus_size: usize, digest_size: usize) -> Option<usize> {
        todo!()
    }

    pub fn cipher_name(&self) -> Option<&'static str> {
        match self {
            Self::PKCS1V15 => Some("RSA-PKCS1v15"),
            Self::OAEP => Some("RSA-OAEP"),
            Self::PSS => None,
        }
    }

    pub fn signature_name(&self) -> Option<&'static str> {
        match self {
            Self::PKCS1V15 => Some("RSA-PKCS1v15"),
            Self::PSS => Some("RSA-PSS"),
            Self::OAEP => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RSA {
    pub bits: usize,
    pub exponent: u32,
}

impl Default for RSA {
    fn default() -> Self {
        Self { bits: 3072, exponent: 65537 }
    }
}

impl RSA {
    pub const MINIMUM_BITS: usize = 2048;

    pub const NAME: &'static str = "RSA";

    pub fn generate(&self, seed: &[u8]) -> Result<(RSAPrivateKey, RSAPublicKey), RSAError> {
        match SignatureProviders::generate(&SignatureProviderRequest::new(Self::NAME).with_seed(seed))? {
            Some((private, public)) => Ok((RSAPrivateKey::decode(&private)?, RSAPublicKey::decode(&public)?)),
            None => todo!(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RSAPrivateKey {
    modulus: Vec<u8>,
    public_exponent: Vec<u8>,
    private_exponent: Vec<u8>,
    primes: Vec<Vec<u8>>,
}

impl RSAPrivateKey {
    pub fn decode(data: &[u8]) -> Result<Self, RSAError> {
        todo!()
    }

    pub fn encode(&self) -> Vec<u8> {
        todo!()
    }

    pub fn public_key(&self) -> RSAPublicKey {
        todo!()
    }

    pub fn bits(&self) -> usize {
        todo!()
    }

    pub fn decrypt(&self, padding: RSAPadding, ciphertext: &[u8], label: &[u8]) -> Result<Vec<u8>, RSAError> {
        let name = padding.cipher_name().ok_or(RSAError::Padding)?;
        let key = self.encode();
        match CipherProviders::decrypt(&CipherProviderRequest::new(name, &key).with_associated(label), ciphertext)? {
            Some(plaintext) => Ok(plaintext),
            None => todo!(),
        }
    }

    pub fn sign(&self, padding: RSAPadding, digest: &[u8], salt: &[u8]) -> Result<RSASignature, RSAError> {
        let name = padding.signature_name().ok_or(RSAError::Padding)?;
        match SignatureProviders::sign(&SignatureProviderRequest::new(name).with_context(salt), &self.encode(), digest)? {
            Some(signature) => Ok(RSASignature { signature }),
            None => todo!(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RSAPublicKey {
    modulus: Vec<u8>,
    exponent: Vec<u8>,
}

impl RSAPublicKey {
    pub fn decode(data: &[u8]) -> Result<Self, RSAError> {
        todo!()
    }

    pub fn encode(&self) -> Vec<u8> {
        todo!()
    }

    pub fn bits(&self) -> usize {
        todo!()
    }

    pub fn encrypt(&self, padding: RSAPadding, plaintext: &[u8], label: &[u8], seed: &[u8]) -> Result<Vec<u8>, RSAError> {
        let name = padding.cipher_name().ok_or(RSAError::Padding)?;
        let key = self.encode();
        match CipherProviders::encrypt(&CipherProviderRequest::new(name, &key).with_nonce(seed).with_associated(label), plaintext)? {
            Some(ciphertext) => Ok(ciphertext),
            None => todo!(),
        }
    }

    pub fn verify(&self, padding: RSAPadding, digest: &[u8], signature: &RSASignature) -> Result<(), RSAError> {
        let name = padding.signature_name().ok_or(RSAError::Padding)?;
        match SignatureProviders::verify(&SignatureProviderRequest::new(name), &self.encode(), digest, &signature.signature)? {
            Some(()) => Ok(()),
            None => todo!(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RSASignature {
    signature: Vec<u8>,
}

impl RSASignature {
    pub fn decode(data: &[u8]) -> Result<Self, RSAError> {
        Ok(Self { signature: data.to_vec() })
    }

    pub fn encode(&self) -> Vec<u8> {
        self.signature.clone()
    }
}

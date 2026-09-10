use alloc::vec::Vec;
use core::fmt;
use crate::errors::RSAError;

use umineko_helpers::provider::{CipherProviderRequest, CipherProviders, SignatureProviderRequest, SignatureProviders};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RSAHash {
    MD2,
    MD5,
    SHA1,
    SHA2_224,
    SHA2_256,
    SHA2_384,
    SHA2_512,
    SHA2_512_224,
    SHA2_512_256,
    SHA3_224,
    SHA3_256,
    SHA3_384,
    SHA3_512,
    MD5_SHA1,
}

impl RSAHash {
    pub const ALL: [Self; 14] = [Self::MD2, Self::MD5, Self::SHA1, Self::SHA2_224, Self::SHA2_256, Self::SHA2_384, Self::SHA2_512, Self::SHA2_512_224, Self::SHA2_512_256, Self::SHA3_224, Self::SHA3_256, Self::SHA3_384, Self::SHA3_512, Self::MD5_SHA1];

    pub fn digest_size(&self) -> usize {
        match self {
            Self::MD2 => 16,
            Self::MD5 => 16,
            Self::SHA1 => 20,
            Self::SHA2_224 => 28,
            Self::SHA2_256 => 32,
            Self::SHA2_384 => 48,
            Self::SHA2_512 => 64,
            Self::SHA2_512_224 => 28,
            Self::SHA2_512_256 => 32,
            Self::SHA3_224 => 28,
            Self::SHA3_256 => 32,
            Self::SHA3_384 => 48,
            Self::SHA3_512 => 64,
            Self::MD5_SHA1 => 36,
        }
    }

    pub fn digest_info(&self) -> Option<&'static [u8]> {
        match self {
            Self::MD2 => Some(&[0x30, 0x20, 0x30, 0x0C, 0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x02, 0x05, 0x00, 0x04, 0x10]),
            Self::MD5 => Some(&[0x30, 0x20, 0x30, 0x0C, 0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10]),
            Self::SHA1 => Some(&[0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14]),
            Self::SHA2_224 => Some(&[0x30, 0x2D, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1C]),
            Self::SHA2_256 => Some(&[0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20]),
            Self::SHA2_384 => Some(&[0x30, 0x41, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30]),
            Self::SHA2_512 => Some(&[0x30, 0x51, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40]),
            Self::SHA2_512_224 => Some(&[0x30, 0x2D, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05, 0x05, 0x00, 0x04, 0x1C]),
            Self::SHA2_512_256 => Some(&[0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06, 0x05, 0x00, 0x04, 0x20]),
            Self::SHA3_224 => Some(&[0x30, 0x2D, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07, 0x05, 0x00, 0x04, 0x1C]),
            Self::SHA3_256 => Some(&[0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08, 0x05, 0x00, 0x04, 0x20]),
            Self::SHA3_384 => Some(&[0x30, 0x41, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09, 0x05, 0x00, 0x04, 0x30]),
            Self::SHA3_512 => Some(&[0x30, 0x51, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0A, 0x05, 0x00, 0x04, 0x40]),
            Self::MD5_SHA1 => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MD2 => "MD2",
            Self::MD5 => "MD5",
            Self::SHA1 => "SHA-1",
            Self::SHA2_224 => "SHA-224",
            Self::SHA2_256 => "SHA-256",
            Self::SHA2_384 => "SHA-384",
            Self::SHA2_512 => "SHA-512",
            Self::SHA2_512_224 => "SHA-512/224",
            Self::SHA2_512_256 => "SHA-512/256",
            Self::SHA3_224 => "SHA3-224",
            Self::SHA3_256 => "SHA3-256",
            Self::SHA3_384 => "SHA3-384",
            Self::SHA3_512 => "SHA3-512",
            Self::MD5_SHA1 => "MD5-SHA1",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|hash| hash.as_str() == name)
    }
}

impl fmt::Display for RSAHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RSAEncryptionPadding {
    PKCS1V15,
    OAEP { hash: RSAHash, mask: RSAHash },
}

impl RSAEncryptionPadding {
    pub fn name(&self) -> &'static str {
        match self {
            Self::PKCS1V15 => "RSA-PKCS1v15",
            Self::OAEP { .. } => "RSA-OAEP",
        }
    }

    pub fn maximum_length(&self, modulus_size: usize) -> Option<usize> {
        match self {
            Self::PKCS1V15 => modulus_size.checked_sub(11),
            Self::OAEP { hash, .. } => modulus_size.checked_sub(2 * hash.digest_size() + 2),
        }
    }

    pub fn request<'a>(&self, key: &'a [u8], label: &'a [u8]) -> CipherProviderRequest<'a> {
        let request = CipherProviderRequest::new(self.name(), key).with_associated(label);
        match self {
            Self::PKCS1V15 => request,
            Self::OAEP { hash, mask } => request.with_digest(hash.as_str()).with_mask(mask.as_str()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RSASignaturePadding {
    PKCS1V15(RSAHash),
    PSS { hash: RSAHash, mask: RSAHash, salt_size: usize },
}

impl RSASignaturePadding {
    pub fn name(&self) -> &'static str {
        match self {
            Self::PKCS1V15(_) => "RSA-PKCS1v15",
            Self::PSS { .. } => "RSA-PSS",
        }
    }

    pub fn hash(&self) -> RSAHash {
        match self {
            Self::PKCS1V15(hash) => *hash,
            Self::PSS { hash, .. } => *hash,
        }
    }

    pub fn request<'a>(&self, salt: &'a [u8]) -> SignatureProviderRequest<'a> {
        let request = SignatureProviderRequest::new(self.name()).with_digest(self.hash().as_str()).with_context(salt);
        match self {
            Self::PKCS1V15(_) => request,
            Self::PSS { mask, salt_size, .. } => request.with_mask(mask.as_str()).with_salt_size(*salt_size),
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

    pub fn decrypt(&self, padding: RSAEncryptionPadding, ciphertext: &[u8], label: &[u8]) -> Result<Vec<u8>, RSAError> {
        let key = self.encode();
        match CipherProviders::decrypt(&padding.request(&key, label), ciphertext)? {
            Some(plaintext) => Ok(plaintext),
            None => todo!(),
        }
    }

    pub fn sign(&self, padding: RSASignaturePadding, digest: &[u8], salt: &[u8]) -> Result<RSASignature, RSAError> {
        if matches!(padding, RSASignaturePadding::PSS { salt_size, .. } if salt.len() != salt_size) {
            return Err(RSAError::Padding);
        }
        match SignatureProviders::sign(&padding.request(salt), &self.encode(), digest)? {
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

    pub fn encrypt(&self, padding: RSAEncryptionPadding, plaintext: &[u8], label: &[u8], seed: &[u8]) -> Result<Vec<u8>, RSAError> {
        let key = self.encode();
        match CipherProviders::encrypt(&padding.request(&key, label).with_nonce(seed), plaintext)? {
            Some(ciphertext) => Ok(ciphertext),
            None => todo!(),
        }
    }

    pub fn verify(&self, padding: RSASignaturePadding, digest: &[u8], signature: &RSASignature) -> Result<(), RSAError> {
        match SignatureProviders::verify(&padding.request(&[]), &self.encode(), digest, &signature.signature)? {
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

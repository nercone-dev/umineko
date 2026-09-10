use alloc::vec::Vec;
use core::fmt;
use crate::errors::HMACError;

use umineko_helpers::provider::{HashProvider, HashProviderRequest, HashProviders, ProviderBackend};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HMACHash {
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
    SM3,
    Streebog256,
    Streebog512,
    AsconHash256,
}

impl HMACHash {
    pub const ALL: [Self; 16] = [Self::MD5, Self::SHA1, Self::SHA2_224, Self::SHA2_256, Self::SHA2_384, Self::SHA2_512, Self::SHA2_512_224, Self::SHA2_512_256, Self::SHA3_224, Self::SHA3_256, Self::SHA3_384, Self::SHA3_512, Self::SM3, Self::Streebog256, Self::Streebog512, Self::AsconHash256];

    pub fn digest_size(&self) -> usize {
        match self {
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
            Self::SM3 => 32,
            Self::Streebog256 => 32,
            Self::Streebog512 => 64,
            Self::AsconHash256 => 32,
        }
    }

    pub fn block_size(&self) -> usize {
        match self {
            Self::MD5 => 64,
            Self::SHA1 => 64,
            Self::SHA2_224 => 64,
            Self::SHA2_256 => 64,
            Self::SHA2_384 => 128,
            Self::SHA2_512 => 128,
            Self::SHA2_512_224 => 128,
            Self::SHA2_512_256 => 128,
            Self::SHA3_224 => 144,
            Self::SHA3_256 => 136,
            Self::SHA3_384 => 104,
            Self::SHA3_512 => 72,
            Self::SM3 => 64,
            Self::Streebog256 => 64,
            Self::Streebog512 => 64,
            Self::AsconHash256 => 64,
        }
    }

    pub fn minimum_tag_size(&self) -> usize {
        core::cmp::max(self.digest_size() / 2, 10)
    }

    pub fn hash_name(&self) -> &'static str {
        match self {
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
            Self::SM3 => "SM3",
            Self::Streebog256 => "Streebog-256",
            Self::Streebog512 => "Streebog-512",
            Self::AsconHash256 => "Ascon-Hash256",
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MD5 => "HMAC-MD5",
            Self::SHA1 => "HMAC-SHA-1",
            Self::SHA2_224 => "HMAC-SHA-224",
            Self::SHA2_256 => "HMAC-SHA-256",
            Self::SHA2_384 => "HMAC-SHA-384",
            Self::SHA2_512 => "HMAC-SHA-512",
            Self::SHA2_512_224 => "HMAC-SHA-512/224",
            Self::SHA2_512_256 => "HMAC-SHA-512/256",
            Self::SHA3_224 => "HMAC-SHA3-224",
            Self::SHA3_256 => "HMAC-SHA3-256",
            Self::SHA3_384 => "HMAC-SHA3-384",
            Self::SHA3_512 => "HMAC-SHA3-512",
            Self::SM3 => "HMAC-SM3",
            Self::Streebog256 => "HMAC-Streebog-256",
            Self::Streebog512 => "HMAC-Streebog-512",
            Self::AsconHash256 => "HMAC-Ascon-Hash256",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|hash| hash.as_str() == name)
    }
}

impl fmt::Display for HMACHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug)]
pub struct HMAC {
    hash: HMACHash,
    key: Vec<u8>,
    backend: ProviderBackend<dyn HashProvider>,
}

impl HMAC {
    pub fn new(hash: HMACHash, key: &[u8]) -> Self {
        match HashProviders::backend(&Self::request(hash, key)) {
            ProviderBackend::Builtin => todo!(),
            backend => Self { hash, key: key.to_vec(), backend },
        }
    }

    pub fn request(hash: HMACHash, key: &[u8]) -> HashProviderRequest<'_> {
        HashProviderRequest::new(hash.as_str()).with_key(key)
    }

    pub fn hash(&self) -> HMACHash {
        self.hash
    }

    pub fn update(&mut self, data: &[u8]) {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => provider.update(*handle, data),
        }
    }

    pub fn finalize(self, tag: &mut [u8]) -> usize {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => provider.finalize(*handle, tag),
        }
    }

    pub fn reset(&mut self) {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => provider.reset(*handle),
        }
    }

    pub fn verify(self, tag: &[u8]) -> Result<(), HMACError> {
        if tag.len() < self.hash.minimum_tag_size() || tag.len() > self.hash.digest_size() {
            return Err(HMACError::Length);
        }
        let mut computed = alloc::vec![0; self.hash.digest_size()];
        let length = self.finalize(&mut computed);
        if tag.len() > length {
            return Err(HMACError::Length);
        }
        let mut difference = 0;
        for (left, right) in computed.iter().zip(tag) {
            difference |= left ^ right;
        }
        match difference {
            0 => Ok(()),
            _ => Err(HMACError::Authentication),
        }
    }

    pub fn tag(hash: HMACHash, key: &[u8], data: &[u8], tag: &mut [u8]) -> usize {
        match HashProviders::digest(&Self::request(hash, key), data, tag) {
            Some(length) => length,
            None => todo!(),
        }
    }
}

impl Clone for HMAC {
    fn clone(&self) -> Self {
        Self { hash: self.hash, key: self.key.clone(), backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)) }
    }
}

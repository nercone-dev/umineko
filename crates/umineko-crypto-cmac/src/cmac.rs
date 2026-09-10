use alloc::vec::Vec;
use core::fmt;
use crate::errors::CMACError;

use umineko_helpers::provider::{HashProvider, HashProviderRequest, HashProviders, ProviderBackend};
use umineko_crypto_aes::AES;
use umineko_crypto_camellia::Camellia;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CMACCipher {
    AES128,
    AES192,
    AES256,
    Camellia128,
    Camellia192,
    Camellia256,
}

impl CMACCipher {
    pub const ALL: [Self; 6] = [Self::AES128, Self::AES192, Self::AES256, Self::Camellia128, Self::Camellia192, Self::Camellia256];

    pub fn key_size(&self) -> usize {
        match self {
            Self::AES128 => AES::V128.key_size(),
            Self::AES192 => AES::V192.key_size(),
            Self::AES256 => AES::V256.key_size(),
            Self::Camellia128 => Camellia::V128.key_size(),
            Self::Camellia192 => Camellia::V192.key_size(),
            Self::Camellia256 => Camellia::V256.key_size(),
        }
    }

    pub fn block_size(&self) -> usize {
        match self {
            Self::AES128 | Self::AES192 | Self::AES256 => AES::BLOCK_SIZE,
            Self::Camellia128 | Self::Camellia192 | Self::Camellia256 => Camellia::BLOCK_SIZE,
        }
    }

    pub fn tag_size(&self) -> usize {
        self.block_size()
    }

    pub fn minimum_tag_size(&self) -> usize {
        8
    }

    pub fn cipher_name(&self) -> &'static str {
        match self {
            Self::AES128 => AES::V128.as_str(),
            Self::AES192 => AES::V192.as_str(),
            Self::AES256 => AES::V256.as_str(),
            Self::Camellia128 => Camellia::V128.as_str(),
            Self::Camellia192 => Camellia::V192.as_str(),
            Self::Camellia256 => Camellia::V256.as_str(),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AES128 => "CMAC-AES-128",
            Self::AES192 => "CMAC-AES-192",
            Self::AES256 => "CMAC-AES-256",
            Self::Camellia128 => "CMAC-Camellia-128",
            Self::Camellia192 => "CMAC-Camellia-192",
            Self::Camellia256 => "CMAC-Camellia-256",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|cipher| cipher.as_str() == name)
    }
}

impl fmt::Display for CMACCipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug)]
pub struct CMAC {
    cipher: CMACCipher,
    key: Vec<u8>,
    backend: ProviderBackend<dyn HashProvider>,
}

impl CMAC {
    pub fn new(cipher: CMACCipher, key: &[u8]) -> Result<Self, CMACError> {
        if key.len() != cipher.key_size() {
            return Err(CMACError::Key);
        }
        match HashProviders::backend(&Self::request(cipher, key)) {
            ProviderBackend::Builtin => todo!(),
            backend => Ok(Self { cipher, key: key.to_vec(), backend }),
        }
    }

    pub fn request(cipher: CMACCipher, key: &[u8]) -> HashProviderRequest<'_> {
        HashProviderRequest::new(cipher.as_str()).with_key(key)
    }

    pub fn cipher(&self) -> CMACCipher {
        self.cipher
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

    pub fn verify(self, tag: &[u8]) -> Result<(), CMACError> {
        if tag.len() < self.cipher.minimum_tag_size() || tag.len() > self.cipher.tag_size() {
            return Err(CMACError::Length);
        }
        let mut computed = alloc::vec![0; self.cipher.tag_size()];
        let length = self.finalize(&mut computed);
        if tag.len() > length {
            return Err(CMACError::Length);
        }
        let mut difference = 0;
        for (left, right) in computed.iter().zip(tag) {
            difference |= left ^ right;
        }
        match difference {
            0 => Ok(()),
            _ => Err(CMACError::Authentication),
        }
    }

    pub fn tag(cipher: CMACCipher, key: &[u8], data: &[u8], tag: &mut [u8]) -> Result<usize, CMACError> {
        if key.len() != cipher.key_size() {
            return Err(CMACError::Key);
        }
        match HashProviders::digest(&Self::request(cipher, key), data, tag) {
            Some(length) => Ok(length),
            None => todo!(),
        }
    }
}

impl Clone for CMAC {
    fn clone(&self) -> Self {
        Self { cipher: self.cipher, key: self.key.clone(), backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)) }
    }
}

use alloc::vec::Vec;
use crate::errors::SSHError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SSHCipher {
    CHACHA20_POLY1305,
    AES128_GCM,
    AES256_GCM,
    AES128_CTR,
    AES192_CTR,
    AES256_CTR,
}

impl SSHCipher {
    pub fn as_str(&self) -> &'static str {
        todo!()
    }

    pub fn from_name(name: &str) -> Option<Self> {
        todo!()
    }

    pub fn authenticated(&self) -> bool {
        matches!(self, Self::CHACHA20_POLY1305 | Self::AES128_GCM | Self::AES256_GCM)
    }

    pub fn key_size(&self) -> usize {
        todo!()
    }

    pub fn nonce_size(&self) -> usize {
        todo!()
    }

    pub fn block_size(&self) -> usize {
        todo!()
    }

    pub fn tag_size(&self) -> usize {
        todo!()
    }

    pub fn encrypt(&self, key: &[u8], sequence: u32, payload: &[u8]) -> Result<Vec<u8>, SSHError> {
        todo!()
    }

    pub fn decrypt(&self, key: &[u8], sequence: u32, data: &[u8]) -> Result<Vec<u8>, SSHError> {
        todo!()
    }
}

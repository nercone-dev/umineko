use alloc::vec::Vec;
use crate::errors::SSHError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SSHMac {
    HMAC_SHA2_256,
    HMAC_SHA2_512,
    HMAC_SHA2_256_ETM,
    HMAC_SHA2_512_ETM,
    Implicit,
}

impl SSHMac {
    pub fn as_str(&self) -> &'static str {
        todo!()
    }

    pub fn from_name(name: &str) -> Option<Self> {
        todo!()
    }

    pub fn encrypt_then_mac(&self) -> bool {
        matches!(self, Self::HMAC_SHA2_256_ETM | Self::HMAC_SHA2_512_ETM)
    }

    pub fn key_size(&self) -> usize {
        todo!()
    }

    pub fn tag_size(&self) -> usize {
        todo!()
    }

    pub fn compute(&self, key: &[u8], sequence: u32, data: &[u8]) -> Result<Vec<u8>, SSHError> {
        todo!()
    }

    pub fn verify(&self, key: &[u8], sequence: u32, data: &[u8], tag: &[u8]) -> Result<(), SSHError> {
        todo!()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SSHCompression {
    None,
    Zlib,
    ZlibDelayed,
}

impl SSHCompression {
    pub fn as_str(&self) -> &'static str {
        todo!()
    }

    pub fn from_name(name: &str) -> Option<Self> {
        todo!()
    }

    pub fn delayed(&self) -> bool {
        matches!(self, Self::ZlibDelayed)
    }
}

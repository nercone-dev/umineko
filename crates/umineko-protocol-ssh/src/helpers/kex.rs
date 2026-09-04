use alloc::vec::Vec;
use crate::errors::SSHError;
use crate::types::SSHRole;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SSHKeyExchangeState {
    Initial,
    Negotiating,
    Exchanging,
    Confirming,
    Established,
}

impl SSHKeyExchangeState {
    pub fn established(&self) -> bool {
        matches!(self, Self::Established)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SSHKeyExchange {
    CURVE25519_SHA256,
    ECDH_SHA2_NISTP256,
    ECDH_SHA2_NISTP384,
    ECDH_SHA2_NISTP521,
    DIFFIE_HELLMAN_GROUP14_SHA256,
    DIFFIE_HELLMAN_GROUP16_SHA512,
    MLKEM768_X25519_SHA256,
    SNTRUP761_X25519_SHA512,
}

impl SSHKeyExchange {
    pub fn as_str(&self) -> &'static str {
        todo!()
    }

    pub fn from_name(name: &str) -> Option<Self> {
        todo!()
    }

    pub fn post_quantum(&self) -> bool {
        matches!(self, Self::MLKEM768_X25519_SHA256 | Self::SNTRUP761_X25519_SHA512)
    }

    pub fn digest_size(&self) -> usize {
        todo!()
    }

    pub fn select(offered: &[Self], supported: &[Self], role: SSHRole) -> Option<Self> {
        todo!()
    }

    pub fn generate(&self, seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), SSHError> {
        todo!()
    }

    pub fn exchange(&self, private: &[u8], peer: &[u8]) -> Result<Vec<u8>, SSHError> {
        todo!()
    }
}

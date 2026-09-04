use alloc::{string::String, vec::Vec};
use crate::errors::SSHError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SSHKeyType {
    SSH_ED25519,
    ECDSA_SHA2_NISTP256,
    ECDSA_SHA2_NISTP384,
    ECDSA_SHA2_NISTP521,
    RSA_SHA2_256,
    RSA_SHA2_512,
    ML_DSA_65,
    ML_DSA_87,
}

impl SSHKeyType {
    pub fn as_str(&self) -> &'static str {
        todo!()
    }

    pub fn from_name(name: &str) -> Option<Self> {
        todo!()
    }

    pub fn post_quantum(&self) -> bool {
        matches!(self, Self::ML_DSA_65 | Self::ML_DSA_87)
    }

    pub fn secure(&self) -> bool {
        true
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SSHKey {
    pub kind: SSHKeyType,
    pub blob: Vec<u8>,
    pub comment: Option<String>,
}

impl SSHKey {
    pub fn decode(data: &[u8]) -> Result<Self, SSHError> {
        todo!()
    }

    pub fn encode(&self) -> Result<Vec<u8>, SSHError> {
        todo!()
    }

    pub fn parse(line: &str) -> Result<Self, SSHError> {
        todo!()
    }

    pub fn fingerprint(&self) -> Result<SSHFingerprint, SSHError> {
        todo!()
    }

    pub fn sign(&self, private: &[u8], data: &[u8]) -> Result<Vec<u8>, SSHError> {
        todo!()
    }

    pub fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), SSHError> {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SSHFingerprint(Vec<u8>);

impl SSHFingerprint {
    pub fn as_slice(&self) -> &[u8] {
        todo!()
    }

    pub fn to_string(&self) -> String {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SSHKnownHosts {
    entries: Vec<(String, SSHKey)>,
}

impl SSHKnownHosts {
    pub fn new() -> Self {
        todo!()
    }

    pub fn insert(&mut self, host: &str, key: SSHKey) {
        todo!()
    }

    pub fn remove(&mut self, host: &str) {
        todo!()
    }

    pub fn get(&self, host: &str) -> Option<&SSHKey> {
        todo!()
    }

    pub fn verify(&self, host: &str, key: &SSHKey) -> Result<bool, SSHError> {
        todo!()
    }

    pub fn parse(data: &[u8]) -> Result<Self, SSHError> {
        todo!()
    }

    pub fn encode(&self) -> Result<Vec<u8>, SSHError> {
        todo!()
    }
}

impl Default for SSHKnownHosts {
    fn default() -> Self {
        Self::new()
    }
}

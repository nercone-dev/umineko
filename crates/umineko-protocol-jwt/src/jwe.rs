use alloc::{string::String, vec::Vec};
use crate::errors::JWTError;
use crate::types::{JWTHeader, JWTLimits};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JWEAlgorithm {
    RSA_OAEP,
    RSA_OAEP_256,
    A128KW,
    A192KW,
    A256KW,
    ECDH_ES,
    ECDH_ES_A128KW,
    ECDH_ES_A256KW,
    PBES2_HS256_A128KW,
    Direct,
}

impl JWEAlgorithm {
    pub fn as_str(&self) -> &'static str {
        todo!()
    }

    pub fn from_name(name: &str) -> Option<Self> {
        todo!()
    }

    pub fn wraps_key(&self) -> bool {
        !matches!(self, Self::Direct)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JWEEncryption {
    A128CBC_HS256,
    A192CBC_HS384,
    A256CBC_HS512,
    A128GCM,
    A192GCM,
    A256GCM,
}

impl JWEEncryption {
    pub fn as_str(&self) -> &'static str {
        todo!()
    }

    pub fn from_name(name: &str) -> Option<Self> {
        todo!()
    }

    pub fn key_size(&self) -> usize {
        todo!()
    }

    pub fn nonce_size(&self) -> usize {
        todo!()
    }

    pub fn tag_size(&self) -> usize {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JWE {
    pub header: JWTHeader,
    pub algorithm: JWEAlgorithm,
    pub encryption: JWEEncryption,
    pub encrypted_key: Vec<u8>,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub tag: Vec<u8>,
}

impl JWE {
    pub fn encrypt(algorithm: JWEAlgorithm, encryption: JWEEncryption, plaintext: &[u8], key: &[u8], seed: &[u8]) -> Result<Self, JWTError> {
        todo!()
    }

    pub fn decrypt(&self, key: &[u8]) -> Result<Vec<u8>, JWTError> {
        todo!()
    }

    pub fn encode(&self) -> Result<String, JWTError> {
        todo!()
    }

    pub fn decode(text: &str, limits: JWTLimits) -> Result<Self, JWTError> {
        todo!()
    }
}

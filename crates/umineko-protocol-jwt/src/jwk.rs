use alloc::{string::String, vec::Vec};
use crate::errors::JWTError;
use crate::types::{JWTAlgorithm, JWTLimits};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JWKUse {
    Signature,
    Encryption,
}

impl JWKUse {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Signature => "sig",
            Self::Encryption => "enc",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JWK {
    pub kind: String,
    pub id: Option<String>,
    pub key_use: Option<JWKUse>,
    pub algorithm: Option<JWTAlgorithm>,
    pub curve: Option<String>,
    pub parameters: Vec<(String, Vec<u8>)>,
    pub certificates: Vec<Vec<u8>>,
}

impl JWK {
    pub fn encode(&self) -> Result<String, JWTError> {
        todo!()
    }

    pub fn decode(text: &str, limits: JWTLimits) -> Result<Self, JWTError> {
        todo!()
    }

    pub fn public(&self) -> Self {
        todo!()
    }

    pub fn private(&self) -> bool {
        todo!()
    }

    pub fn thumbprint(&self) -> Result<Vec<u8>, JWTError> {
        todo!()
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, JWTError> {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JWKSet {
    keys: Vec<JWK>,
}

impl JWKSet {
    pub fn new() -> Self {
        todo!()
    }

    pub fn insert(&mut self, key: JWK) {
        todo!()
    }

    pub fn remove(&mut self, id: &str) {
        todo!()
    }

    pub fn get(&self, id: Option<&str>, key_use: Option<JWKUse>, algorithm: Option<JWTAlgorithm>) -> Option<&JWK> {
        todo!()
    }

    pub fn keys(&self) -> &[JWK] {
        todo!()
    }

    pub fn encode(&self) -> Result<String, JWTError> {
        todo!()
    }

    pub fn decode(text: &str, limits: JWTLimits) -> Result<Self, JWTError> {
        todo!()
    }
}

impl Default for JWKSet {
    fn default() -> Self {
        Self::new()
    }
}

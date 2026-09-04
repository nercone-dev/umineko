use alloc::{string::String, vec::Vec};
use crate::errors::JWTError;
use crate::types::{JWT, JWTAlgorithm, JWTHeader, JWTClaims, JWTLimits};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JWS {
    pub header: JWTHeader,
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
}

impl JWS {
    pub fn encode(&self) -> Result<String, JWTError> {
        todo!()
    }

    pub fn decode(text: &str, limits: JWTLimits) -> Result<Self, JWTError> {
        todo!()
    }

    pub fn encode_detached(&self) -> Result<String, JWTError> {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JWSSigner {
    pub algorithm: JWTAlgorithm,
    pub key_id: Option<String>,
}

impl JWSSigner {
    pub fn sign(&self, claims: &JWTClaims, key: &[u8]) -> Result<JWT, JWTError> {
        todo!()
    }

    pub fn sign_raw(&self, payload: &[u8], key: &[u8]) -> Result<JWS, JWTError> {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct JWSVerifier {
    pub algorithms: Vec<JWTAlgorithm>,
    pub limits: JWTLimits,
}

impl JWSVerifier {
    pub fn new(algorithms: Vec<JWTAlgorithm>, limits: JWTLimits) -> Self {
        todo!()
    }

    pub fn verify(&self, text: &str, key: &[u8], now: u64, audience: Option<&str>) -> Result<JWT, JWTError> {
        todo!()
    }

    pub fn verify_raw(&self, jws: &JWS, key: &[u8]) -> Result<Vec<u8>, JWTError> {
        todo!()
    }
}

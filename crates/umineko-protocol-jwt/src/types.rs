use alloc::{string::String, vec::Vec};
use core::fmt;
use crate::errors::JWTError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JWTAlgorithm {
    None,
    HS256,
    HS384,
    HS512,
    RS256,
    RS384,
    RS512,
    ES256,
    ES384,
    ES512,
    PS256,
    PS384,
    PS512,
    EdDSA,
    ML_DSA_44,
    ML_DSA_65,
    ML_DSA_87,
}

impl JWTAlgorithm {
    pub fn as_str(&self) -> &'static str {
        todo!()
    }

    pub fn from_name(name: &str) -> Option<Self> {
        todo!()
    }

    pub fn symmetric(&self) -> bool {
        matches!(self, Self::HS256 | Self::HS384 | Self::HS512)
    }

    pub fn secure(&self) -> bool {
        !matches!(self, Self::None)
    }

    pub fn digest_size(&self) -> usize {
        todo!()
    }
}

impl fmt::Display for JWTAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JWTHeader {
    pub algorithm: JWTAlgorithm,
    pub kind: Option<String>,
    pub key_id: Option<String>,
    pub key_url: Option<String>,
    pub certificates: Vec<Vec<u8>>,
    pub critical: Vec<String>,
    pub extra: Vec<(String, String)>,
}

impl JWTHeader {
    pub fn new(algorithm: JWTAlgorithm) -> Self {
        todo!()
    }

    pub fn encode(&self) -> Result<String, JWTError> {
        todo!()
    }

    pub fn decode(text: &str) -> Result<Self, JWTError> {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JWTClaims {
    pub issuer: Option<String>,
    pub subject: Option<String>,
    pub audience: Vec<String>,
    pub expiration: Option<u64>,
    pub not_before: Option<u64>,
    pub issued_at: Option<u64>,
    pub id: Option<String>,
    pub extra: Vec<(String, String)>,
}

impl JWTClaims {
    pub fn new() -> Self {
        todo!()
    }

    pub fn encode(&self) -> Result<String, JWTError> {
        todo!()
    }

    pub fn decode(text: &str) -> Result<Self, JWTError> {
        todo!()
    }

    pub fn validate(&self, now: u64, audience: Option<&str>, leeway: u64) -> Result<(), JWTError> {
        todo!()
    }
}

impl Default for JWTClaims {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JWT {
    pub header: JWTHeader,
    pub claims: JWTClaims,
    pub signature: Vec<u8>,
}

impl JWT {
    pub const SEPARATOR: char = '.';

    pub fn encode(&self) -> Result<String, JWTError> {
        todo!()
    }

    pub fn decode_unverified(text: &str, limits: JWTLimits) -> Result<Self, JWTError> {
        todo!()
    }

    pub fn signing_input(&self) -> Result<String, JWTError> {
        todo!()
    }
}

impl fmt::Display for JWT {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct JWTLimits {
    pub max_token_size: u32,
    pub max_header_size: u32,
    pub max_claims_size: u32,
    pub max_claim_count: u16,
    pub max_audience_count: u8,
    pub max_certificate_count: u8,
    pub max_key_count: u16,

    pub leeway: u64,
    pub max_lifetime: u64,
}

impl Default for JWTLimits {
    fn default() -> Self {
        Self {
            max_token_size: 64 * 1024,
            max_header_size: 8 * 1024,
            max_claims_size: 32 * 1024,
            max_claim_count: 256,
            max_audience_count: 16,
            max_certificate_count: 8,
            max_key_count: 64,

            leeway: 60,
            max_lifetime: 86400,
        }
    }
}

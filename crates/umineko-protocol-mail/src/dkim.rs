use alloc::{string::String, vec::Vec};
use crate::errors::MailError;
use crate::types::{MailResult, MailLimits};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DKIMCanonicalization {
    Simple,
    Relaxed,
}

impl DKIMCanonicalization {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Simple => "simple",
            Self::Relaxed => "relaxed",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        todo!()
    }

    pub fn canonicalize_header(&self, name: &str, value: &str) -> String {
        todo!()
    }

    pub fn canonicalize_body(&self, body: &[u8]) -> Vec<u8> {
        todo!()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DKIM {
    RSASHA256,
    ED25519SHA256,
}

impl DKIM {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RSASHA256 => "rsa-sha256",
            Self::ED25519SHA256 => "ed25519-sha256",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        todo!()
    }

    pub fn secure(&self) -> bool {
        true
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DKIMSignature {
    pub version: u8,
    pub algorithm: DKIM,
    pub domain: String,
    pub selector: String,
    pub header_canonicalization: DKIMCanonicalization,
    pub body_canonicalization: DKIMCanonicalization,
    pub headers: Vec<String>,
    pub body_hash: Vec<u8>,
    pub signature: Vec<u8>,
    pub timestamp: Option<u64>,
    pub expiration: Option<u64>,
    pub body_length: Option<u64>,
}

impl DKIMSignature {
    pub const HEADER: &'static str = "DKIM-Signature";

    pub fn parse(value: &str) -> Result<Self, MailError> {
        todo!()
    }

    pub fn encode(&self) -> String {
        todo!()
    }

    pub fn key_name(&self) -> String {
        todo!()
    }

    pub fn expired(&self, now: u64) -> bool {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DKIMSigner {
    pub algorithm: DKIM,
    pub domain: String,
    pub selector: String,
    pub headers: Vec<String>,
    pub header_canonicalization: DKIMCanonicalization,
    pub body_canonicalization: DKIMCanonicalization,
}

impl DKIMSigner {
    pub fn sign(&self, headers: &[(String, String)], body: &[u8], key: &[u8], now: u64) -> Result<DKIMSignature, MailError> {
        todo!()
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DKIMVerifier {
    pub limits: MailLimits,
}

impl DKIMVerifier {
    pub fn new(limits: MailLimits) -> Self {
        todo!()
    }

    pub fn verify(&self, signature: &DKIMSignature, headers: &[(String, String)], body: &[u8], key: &[u8], now: u64) -> Result<MailResult, MailError> {
        todo!()
    }

    pub fn verify_all(&self, headers: &[(String, String)], body: &[u8], now: u64) -> Result<Vec<(DKIMSignature, MailResult)>, MailError> {
        todo!()
    }
}

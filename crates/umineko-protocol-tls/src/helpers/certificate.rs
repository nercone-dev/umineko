use alloc::{string::String, vec::Vec};
use crate::errors::TLSError;
use crate::types::TLSSignatureScheme;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TLSCertificate {
    encoded: Vec<u8>,
}

impl TLSCertificate {
    pub fn decode(data: &[u8]) -> Result<Self, TLSError> {
        todo!()
    }

    pub fn encode(&self) -> &[u8] {
        todo!()
    }

    pub fn subject(&self) -> Result<String, TLSError> {
        todo!()
    }

    pub fn issuer(&self) -> Result<String, TLSError> {
        todo!()
    }

    pub fn names(&self) -> Result<Vec<String>, TLSError> {
        todo!()
    }

    pub fn signature_scheme(&self) -> Result<TLSSignatureScheme, TLSError> {
        todo!()
    }

    pub fn matches(&self, name: &str) -> bool {
        todo!()
    }

    pub fn valid(&self, now: f64) -> bool {
        todo!()
    }

    pub fn self_signed(&self) -> bool {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TLSCertificateChain {
    certificates: Vec<TLSCertificate>,
}

impl TLSCertificateChain {
    pub fn new(certificates: Vec<TLSCertificate>) -> Self {
        todo!()
    }

    pub fn leaf(&self) -> Option<&TLSCertificate> {
        todo!()
    }

    pub fn certificates(&self) -> &[TLSCertificate] {
        todo!()
    }

    pub fn len(&self) -> usize {
        todo!()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn encode(&self) -> Result<Vec<u8>, TLSError> {
        todo!()
    }

    pub fn decode(data: &[u8]) -> Result<Self, TLSError> {
        todo!()
    }
}

pub trait TLSCertificateVerifier {
    fn roots(&self) -> &[TLSCertificate];

    fn verify(&self, chain: &TLSCertificateChain, name: Option<&str>, now: f64) -> Result<(), TLSError>;

    fn verify_revocation(&self, chain: &TLSCertificateChain) -> Result<(), TLSError> {
        Ok(())
    }
}

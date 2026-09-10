use alloc::vec::Vec;
use crate::errors::DNSError;
use crate::types::{DNSName, DNSRecord, DNSMessage};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DNSSECAlgorithm {
    RSASHA256,
    RSASHA512,
    ECDSAP256SHA256,
    ECDSAP384SHA384,
    ED25519,
    ED448,
    Unknown(u8),
}

impl DNSSECAlgorithm {
    pub fn number(&self) -> u8 {
        todo!()
    }

    pub fn from_number(number: u8) -> Self {
        todo!()
    }

    pub fn secure(&self) -> bool {
        !matches!(self, Self::Unknown(_))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DNSSECStatus {
    Secure,
    Insecure,
    Bogus,
    Indeterminate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DNSSEC {
    trust_anchors: Vec<DNSRecord>,
}

impl DNSSEC {
    pub fn new(trust_anchors: Vec<DNSRecord>) -> Self {
        todo!()
    }

    pub fn verify(&self, message: &DNSMessage, now: f64) -> Result<DNSSECStatus, DNSError> {
        todo!()
    }

    pub fn verify_records(&self, records: &[DNSRecord], signature: &DNSRecord, key: &DNSRecord, now: f64) -> Result<(), DNSError> {
        todo!()
    }

    pub fn verify_denial(&self, name: &DNSName, records: &[DNSRecord]) -> Result<(), DNSError> {
        todo!()
    }

    pub fn verify_delegation(&self, delegation: &DNSRecord, key: &DNSRecord) -> Result<(), DNSError> {
        todo!()
    }
}

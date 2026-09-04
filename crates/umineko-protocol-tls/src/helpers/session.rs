use alloc::{string::String, vec::Vec};
use crate::errors::TLSError;
use crate::types::{TLSVersion, TLSCipher, TLSLimits};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TLSSessionTicket {
    pub identity: Vec<u8>,
    pub nonce: Vec<u8>,
    pub lifetime: u32,
    pub age_add: u32,
    pub max_early_data: u32,
}

impl TLSSessionTicket {
    pub fn expired(&self, elapsed: f64) -> bool {
        todo!()
    }

    pub fn encode(&self) -> Result<Vec<u8>, TLSError> {
        todo!()
    }

    pub fn decode(data: &[u8]) -> Result<Self, TLSError> {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TLSSession {
    pub name: String,
    pub version: TLSVersion,
    pub cipher: TLSCipher,
    pub secret: Vec<u8>,
    pub ticket: Option<TLSSessionTicket>,
    pub application_protocol: Option<String>,
}

impl TLSSession {
    pub fn usable(&self, elapsed: f64) -> bool {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct TLSSessionStore {
    sessions: Vec<TLSSession>,
    limits: TLSLimits,
}

impl TLSSessionStore {
    pub fn new(limits: TLSLimits) -> Self {
        todo!()
    }

    pub fn insert(&mut self, session: TLSSession) {
        todo!()
    }

    pub fn get(&self, name: &str) -> Option<&TLSSession> {
        todo!()
    }

    pub fn remove(&mut self, name: &str) {
        todo!()
    }

    pub fn expire(&mut self, elapsed: f64) -> usize {
        todo!()
    }

    pub fn clear(&mut self) {
        todo!()
    }

    pub fn len(&self) -> usize {
        todo!()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

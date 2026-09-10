use alloc::{string::String, vec::Vec};
use crate::errors::HTTPError;
use crate::types::HTTPVersion;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HTTPSRecord {
    pub name: String,
    pub priority: u16,
    pub target: String,
    pub application_protocols: Vec<String>,
    pub port: Option<u16>,
    pub ipv4_hints: Vec<[u8; 4]>,
    pub ipv6_hints: Vec<[u8; 16]>,
    pub encrypted_client_hello: Option<Vec<u8>>,
}

impl HTTPSRecord {
    pub fn decode(name: &str, data: &[u8]) -> Result<Self, HTTPError> {
        todo!()
    }

    pub fn encode(&self) -> Result<Vec<u8>, HTTPError> {
        todo!()
    }

    pub fn alias(&self) -> bool {
        self.priority == 0
    }

    pub fn version(&self, supported: &[HTTPVersion]) -> Option<HTTPVersion> {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct HTTPSRecordStore {
    records: Vec<(HTTPSRecord, f64)>,
}

impl HTTPSRecordStore {
    pub fn new() -> Self {
        todo!()
    }

    pub fn insert(&mut self, record: HTTPSRecord, lifetime: f64) {
        todo!()
    }

    pub fn remove(&mut self, name: &str) {
        todo!()
    }

    pub fn get(&self, name: &str) -> Vec<&HTTPSRecord> {
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

impl Default for HTTPSRecordStore {
    fn default() -> Self {
        Self::new()
    }
}

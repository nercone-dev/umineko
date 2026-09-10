use alloc::vec::Vec;
use crate::errors::TLSError;
use crate::types::{TLSVersion, TLSCipher};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TLSSecret {
    EarlyData,
    Handshake,
    Application,
    Resumption,
    Exporter,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TLSKeySchedule {
    version: TLSVersion,
    cipher: Option<TLSCipher>,
    transcript: Vec<u8>,
}

impl TLSKeySchedule {
    pub fn new(version: TLSVersion) -> Self {
        todo!()
    }

    pub fn set_cipher(&mut self, cipher: TLSCipher) {
        todo!()
    }

    pub fn update_transcript(&mut self, data: &[u8]) {
        todo!()
    }

    pub fn transcript_hash(&self) -> Result<Vec<u8>, TLSError> {
        todo!()
    }

    pub fn absorb(&mut self, shared_secret: &[u8]) -> Result<(), TLSError> {
        todo!()
    }

    pub fn derive(&self, secret: TLSSecret) -> Result<Vec<u8>, TLSError> {
        todo!()
    }

    pub fn derive_traffic_keys(&self, secret: TLSSecret) -> Result<(Vec<u8>, Vec<u8>), TLSError> {
        todo!()
    }

    pub fn export(&self, label: &str, context: &[u8], length: usize) -> Result<Vec<u8>, TLSError> {
        todo!()
    }

    pub fn advance(&mut self) -> Result<(), TLSError> {
        todo!()
    }
}

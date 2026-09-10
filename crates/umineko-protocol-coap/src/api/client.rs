use alloc::vec::Vec;
use crate::errors::CoAPError;
use crate::types::{CoAPVersion, CoAPCode, CoAPOption, CoAPLimits};
use crate::protocol::message::CoAPMessage;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoAPClientConfig {
    pub versions: Vec<CoAPVersion>,

    pub confirmable: bool,
    pub block_transfer: bool,
    pub observe: bool,
    pub dtls: bool,
}

impl Default for CoAPClientConfig {
    fn default() -> Self {
        Self {
            versions: [CoAPVersion::V1].to_vec(),

            confirmable: true,
            block_transfer: true,
            observe: true,
            dtls: true,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct CoAPClient {
    pub config: CoAPClientConfig,
    pub limits: CoAPLimits,
}

impl CoAPClient {
    pub fn new(config: CoAPClientConfig, limits: CoAPLimits) -> Self {
        todo!()
    }

    pub async fn request(&self, code: CoAPCode, url: &str, options: &[CoAPOption], payload: &[u8]) -> Result<CoAPMessage, CoAPError> {
        todo!()
    }

    pub async fn get(&self, url: &str) -> Result<CoAPMessage, CoAPError> {
        todo!()
    }

    pub async fn post(&self, url: &str, payload: &[u8]) -> Result<CoAPMessage, CoAPError> {
        todo!()
    }

    pub async fn put(&self, url: &str, payload: &[u8]) -> Result<CoAPMessage, CoAPError> {
        todo!()
    }

    pub async fn delete(&self, url: &str) -> Result<CoAPMessage, CoAPError> {
        todo!()
    }

    pub async fn observe(&self, url: &str) -> Result<CoAPMessage, CoAPError> {
        todo!()
    }

    pub async fn unobserve(&self, url: &str) -> Result<(), CoAPError> {
        todo!()
    }
}

use alloc::vec::Vec;
use crate::errors::NDPError;
use crate::types::{LinkLayerAddress, NDPLimits};
use crate::protocol::router::RouterPrefix;
use crate::helpers::cache::NDPCache;

use umineko_protocol_ip::IPAddress;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NDPClientConfig {
    pub link_layer: Option<LinkLayerAddress>,
    pub address: Option<IPAddress>,
    pub autoconfigure: bool,
    pub duplicate_detection: bool,
}

impl Default for NDPClientConfig {
    fn default() -> Self {
        Self { link_layer: None, address: None, autoconfigure: true, duplicate_detection: true }
    }
}

#[derive(Debug, Clone)]
pub struct NDPClient {
    pub config: NDPClientConfig,
    pub limits: NDPLimits,
    pub cache: NDPCache,
}

impl NDPClient {
    pub fn new(config: NDPClientConfig, limits: NDPLimits) -> Self {
        todo!()
    }

    pub async fn resolve(&mut self, address: IPAddress) -> Result<LinkLayerAddress, NDPError> {
        todo!()
    }

    pub async fn solicit(&mut self) -> Result<Vec<RouterPrefix>, NDPError> {
        todo!()
    }

    pub async fn detect_duplicate(&self, address: IPAddress) -> Result<bool, NDPError> {
        todo!()
    }

    pub async fn advertise(&self) -> Result<(), NDPError> {
        todo!()
    }
}

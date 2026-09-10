use crate::errors::ARPError;
use crate::types::{HardwareAddress, ARPLimits};
use crate::helpers::cache::ARPCache;

use umineko_protocol_ip::IPAddress;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ARPClientConfig {
    pub hardware: Option<HardwareAddress>,
    pub protocol: Option<IPAddress>,
    pub bypass_cache: bool,
}

impl Default for ARPClientConfig {
    fn default() -> Self {
        Self { hardware: None, protocol: None, bypass_cache: false }
    }
}

#[derive(Debug, Clone)]
pub struct ARPClient {
    pub config: ARPClientConfig,
    pub limits: ARPLimits,
    pub cache: ARPCache,
}

impl ARPClient {
    pub fn new(config: ARPClientConfig, limits: ARPLimits) -> Self {
        todo!()
    }

    pub async fn resolve(&mut self, protocol: IPAddress) -> Result<HardwareAddress, ARPError> {
        todo!()
    }

    pub async fn announce(&self) -> Result<(), ARPError> {
        todo!()
    }

    pub async fn probe(&self, protocol: IPAddress) -> Result<Option<HardwareAddress>, ARPError> {
        todo!()
    }
}

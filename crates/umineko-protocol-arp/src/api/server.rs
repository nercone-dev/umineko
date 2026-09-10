use crate::errors::ARPError;
use crate::types::{HardwareAddress, ARPLimits};
use crate::protocol::connection::ARPConnection;

use umineko_protocol_ip::IPAddress;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ARPServerConfig {
    pub hardware: Option<HardwareAddress>,
    pub protocol: Option<IPAddress>,
    pub proxy: bool,
}

impl Default for ARPServerConfig {
    fn default() -> Self {
        Self { hardware: None, protocol: None, proxy: false }
    }
}

///
pub trait ARPHandler {
    async fn on_connection(&self, connection: &mut ARPConnection);
}

#[derive(Debug, Clone, Default)]
pub struct ARPServer {
    pub config: ARPServerConfig,
    pub limits: ARPLimits,
}

impl ARPServer {
    pub fn new(config: ARPServerConfig, limits: ARPLimits) -> Self {
        todo!()
    }

    pub async fn serve<H: ARPHandler>(&self, handler: H) -> Result<(), ARPError> {
        todo!()
    }

    pub fn run<H: ARPHandler>(&self, handler: H, workers: usize) -> Result<(), ARPError> {
        todo!()
    }
}

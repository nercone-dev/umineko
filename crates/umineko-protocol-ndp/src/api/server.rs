use crate::errors::NDPError;
use crate::types::{LinkLayerAddress, NDPLimits};
use crate::protocol::connection::NDPConnection;

use umineko_protocol_ip::IPAddress;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NDPServerConfig {
    pub link_layer: Option<LinkLayerAddress>,
    pub address: Option<IPAddress>,
    pub router: bool,
    pub proxy: bool,
}

impl Default for NDPServerConfig {
    fn default() -> Self {
        Self { link_layer: None, address: None, router: false, proxy: false }
    }
}

///
pub trait NDPHandler {
    async fn on_connection(&self, connection: &mut NDPConnection);
}

#[derive(Debug, Clone, Default)]
pub struct NDPServer {
    pub config: NDPServerConfig,
    pub limits: NDPLimits,
}

impl NDPServer {
    pub fn new(config: NDPServerConfig, limits: NDPLimits) -> Self {
        todo!()
    }

    pub async fn serve<H: NDPHandler>(&self, handler: H) -> Result<(), NDPError> {
        todo!()
    }

    pub fn run<H: NDPHandler>(&self, handler: H, workers: usize) -> Result<(), NDPError> {
        todo!()
    }
}

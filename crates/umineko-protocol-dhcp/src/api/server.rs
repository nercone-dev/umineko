use alloc::vec::Vec;
use crate::errors::DHCPError;
use crate::types::{DHCPVersion, DHCPOption, DHCPLimits};

use crate::protocol::base::DHCPConnection;

use umineko_protocol_ip::IPAddress;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DHCPServerConfig {
    pub versions: Vec<DHCPVersion>,
    pub pools: Vec<(IPAddress, IPAddress)>,
    pub options: Vec<DHCPOption>,

    pub relay: bool,
    pub allow_unknown: bool,
}

impl Default for DHCPServerConfig {
    fn default() -> Self {
        Self {
            versions: [DHCPVersion::V6, DHCPVersion::V4].to_vec(),
            pools: Vec::new(),
            options: Vec::new(),

            relay: false,
            allow_unknown: true,
        }
    }
}

///
pub trait DHCPHandler {
    async fn on_connection(&self, connection: &mut DHCPConnection);
}

#[derive(Debug, Clone, Default)]
pub struct DHCPServer {
    pub config: DHCPServerConfig,
    pub limits: DHCPLimits,
}

impl DHCPServer {
    pub fn new(config: DHCPServerConfig, limits: DHCPLimits) -> Self {
        todo!()
    }

    pub async fn serve<H: DHCPHandler>(&self, handler: H) -> Result<(), DHCPError> {
        todo!()
    }

    pub fn run<H: DHCPHandler>(&self, handler: H, workers: usize) -> Result<(), DHCPError> {
        todo!()
    }
}

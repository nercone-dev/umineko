use alloc::vec::Vec;
use crate::errors::IPError;
use crate::types::{IPVersion, IPAddress, IPProtocol, IPLimits};
use crate::protocol::base::IPConnection;

#[derive(Debug, Clone, PartialEq)]
pub struct IPServerConfig {
    pub versions: Vec<IPVersion>,
    pub protocol: IPProtocol,
    pub addresses: Vec<IPAddress>,
    pub reassemble: bool,
}

impl Default for IPServerConfig {
    fn default() -> Self {
        Self {
            versions: [IPVersion::V6, IPVersion::V4].to_vec(),
            protocol: IPProtocol::Unknown(255),
            addresses: Vec::new(),
            reassemble: true,
        }
    }
}

///
pub trait IPHandler {
    async fn on_connection(&self, connection: &mut IPConnection);
}

#[derive(Debug, Clone, Default)]
pub struct IPServer {
    pub config: IPServerConfig,
    pub limits: IPLimits,
}

impl IPServer {
    pub fn new(config: IPServerConfig, limits: IPLimits) -> Self {
        todo!()
    }

    pub async fn serve<H: IPHandler>(&self, handler: H) -> Result<(), IPError> {
        todo!()
    }

    pub fn run<H: IPHandler>(&self, handler: H, workers: usize) -> Result<(), IPError> {
        todo!()
    }
}

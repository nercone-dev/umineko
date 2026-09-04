use alloc::vec::Vec;
use crate::errors::UDPError;
use crate::types::{UDPEndpoint, UDPLimits};
use crate::protocol::connection::UDPSocket;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UDPServerConfig {
    pub endpoints: Vec<UDPEndpoint>,
    pub checksum: bool,
    pub reuse_address: bool,
    pub reuse_port: bool,
    pub receive_destination: bool,
}

impl Default for UDPServerConfig {
    fn default() -> Self {
        Self {
            endpoints: Vec::new(),
            checksum: true,
            reuse_address: true,
            reuse_port: false,
            receive_destination: true,
        }
    }
}

///
pub trait UDPHandler {
    async fn on_connection(&self, socket: &mut UDPSocket);
}

#[derive(Debug, Clone, Default)]
pub struct UDPServer {
    pub config: UDPServerConfig,
    pub limits: UDPLimits,
}

impl UDPServer {
    pub fn new(config: UDPServerConfig, limits: UDPLimits) -> Self {
        todo!()
    }

    pub async fn serve<H: UDPHandler>(&self, handler: H) -> Result<(), UDPError> {
        todo!()
    }

    pub fn run<H: UDPHandler>(&self, handler: H, workers: usize) -> Result<(), UDPError> {
        todo!()
    }
}

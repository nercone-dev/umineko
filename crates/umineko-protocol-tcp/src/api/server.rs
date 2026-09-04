use alloc::vec::Vec;
use crate::errors::TCPError;
use crate::types::{TCPEndpoint, TCPLimits};
use crate::protocol::connection::TCPConnection;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TCPServerConfig {
    pub endpoints: Vec<TCPEndpoint>,
    pub backlog: u32,
    pub no_delay: bool,
    pub keepalive: bool,
    pub reuse_address: bool,
    pub reuse_port: bool,
}

impl Default for TCPServerConfig {
    fn default() -> Self {
        Self {
            endpoints: Vec::new(),
            backlog: 128,
            no_delay: true,
            keepalive: true,
            reuse_address: true,
            reuse_port: false,
        }
    }
}

///
pub trait TCPHandler {
    async fn on_connection(&self, connection: &mut TCPConnection);
}

#[derive(Debug, Clone, Default)]
pub struct TCPServer {
    pub config: TCPServerConfig,
    pub limits: TCPLimits,
}

impl TCPServer {
    pub fn new(config: TCPServerConfig, limits: TCPLimits) -> Self {
        todo!()
    }

    pub async fn serve<H: TCPHandler>(&self, handler: H) -> Result<(), TCPError> {
        todo!()
    }

    pub fn run<H: TCPHandler>(&self, handler: H, workers: usize) -> Result<(), TCPError> {
        todo!()
    }
}

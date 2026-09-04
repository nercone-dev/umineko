use alloc::vec::Vec;
use crate::errors::UDSError;
use crate::types::{UDSPath, UDSType, UDSLimits};
use crate::protocol::base::UDSConnection;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UDSServerConfig {
    pub kind: UDSType,
    pub paths: Vec<UDSPath>,
    pub backlog: u32,
    pub mode: u32,
    pub replace: bool,
    pub receive_ancillary: bool,
}

impl Default for UDSServerConfig {
    fn default() -> Self {
        Self {
            kind: UDSType::Stream,
            paths: Vec::new(),
            backlog: 128,
            mode: 0o600,
            replace: false,
            receive_ancillary: true,
        }
    }
}

///
pub trait UDSHandler {
    async fn on_connection(&self, connection: &mut UDSConnection);
}

#[derive(Debug, Clone, Default)]
pub struct UDSServer {
    pub config: UDSServerConfig,
    pub limits: UDSLimits,
}

impl UDSServer {
    pub fn new(config: UDSServerConfig, limits: UDSLimits) -> Self {
        todo!()
    }

    pub async fn serve<H: UDSHandler>(&self, handler: H) -> Result<(), UDSError> {
        todo!()
    }

    pub fn run<H: UDSHandler>(&self, handler: H, workers: usize) -> Result<(), UDSError> {
        todo!()
    }
}

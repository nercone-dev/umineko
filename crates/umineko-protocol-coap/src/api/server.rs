use alloc::vec::Vec;
use crate::errors::CoAPError;
use crate::types::{CoAPVersion, CoAPLimits};
use crate::protocol::base::CoAPConnection;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoAPServerConfig {
    pub versions: Vec<CoAPVersion>,

    pub block_transfer: bool,
    pub observe: bool,
    pub require_dtls: bool,
    pub multicast: bool,
}

impl Default for CoAPServerConfig {
    fn default() -> Self {
        Self {
            versions: [CoAPVersion::V1].to_vec(),

            block_transfer: true,
            observe: true,
            require_dtls: true,
            multicast: false,
        }
    }
}

///
pub trait CoAPHandler {
    async fn on_connection(&self, connection: &mut CoAPConnection);
}

#[derive(Debug, Clone, Default)]
pub struct CoAPServer {
    pub config: CoAPServerConfig,
    pub limits: CoAPLimits,
}

impl CoAPServer {
    pub fn new(config: CoAPServerConfig, limits: CoAPLimits) -> Self {
        todo!()
    }

    pub async fn serve<H: CoAPHandler>(&self, handler: H) -> Result<(), CoAPError> {
        todo!()
    }

    pub fn run<H: CoAPHandler>(&self, handler: H, workers: usize) -> Result<(), CoAPError> {
        todo!()
    }
}

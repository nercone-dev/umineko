use alloc::vec::Vec;
use crate::errors::IMAPError;
use crate::types::{IMAPCapability, IMAPLimits};
use crate::protocol::base::IMAPConnection;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IMAPServerConfig {
    pub capabilities: Vec<IMAPCapability>,

    pub starttls: bool,
    pub require_starttls: bool,
    pub idle: bool,
}

impl Default for IMAPServerConfig {
    fn default() -> Self {
        Self {
            capabilities: Vec::new(),

            starttls: true,
            require_starttls: true,
            idle: true,
        }
    }
}

///
pub trait IMAPHandler {
    async fn on_connection(&self, connection: &mut IMAPConnection);
}

#[derive(Debug, Clone, Default)]
pub struct IMAPServer {
    pub config: IMAPServerConfig,
    pub limits: IMAPLimits,
}

impl IMAPServer {
    pub fn new(config: IMAPServerConfig, limits: IMAPLimits) -> Self {
        todo!()
    }

    pub async fn serve<H: IMAPHandler>(&self, handler: H) -> Result<(), IMAPError> {
        todo!()
    }

    pub fn run<H: IMAPHandler>(&self, handler: H, workers: usize) -> Result<(), IMAPError> {
        todo!()
    }
}

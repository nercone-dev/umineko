use alloc::{string::String, vec::Vec};
use crate::errors::FTPError;
use crate::types::FTPLimits;
use crate::protocol::data::FTPDataMode;
use crate::protocol::base::FTPConnection;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FTPServerConfig {
    pub features: Vec<String>,
    pub root: String,
    pub data_modes: Vec<FTPDataMode>,

    pub anonymous: bool,
    pub secure: bool,
    pub require_secure: bool,
    pub writable: bool,
}

impl Default for FTPServerConfig {
    fn default() -> Self {
        Self {
            features: Vec::new(),
            root: String::new(),
            data_modes: [FTPDataMode::Passive].to_vec(),

            anonymous: false,
            secure: true,
            require_secure: true,
            writable: false,
        }
    }
}

///
pub trait FTPHandler {
    async fn on_connection(&self, connection: &mut FTPConnection);
}

#[derive(Debug, Clone, Default)]
pub struct FTPServer {
    pub config: FTPServerConfig,
    pub limits: FTPLimits,
}

impl FTPServer {
    pub fn new(config: FTPServerConfig, limits: FTPLimits) -> Self {
        todo!()
    }

    pub async fn serve<H: FTPHandler>(&self, handler: H) -> Result<(), FTPError> {
        todo!()
    }

    pub fn run<H: FTPHandler>(&self, handler: H, workers: usize) -> Result<(), FTPError> {
        todo!()
    }
}

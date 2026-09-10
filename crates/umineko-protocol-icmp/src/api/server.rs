use alloc::vec::Vec;
use crate::errors::ICMPError;
use crate::types::{ICMPVersion, ICMPLimits};

use crate::protocol::base::ICMPConnection;

use umineko_protocol_ip::IPAddress;

#[derive(Debug, Clone, PartialEq)]
pub struct ICMPServerConfig {
    pub versions: Vec<ICMPVersion>,
    pub addresses: Vec<IPAddress>,
    pub reply_echo: bool,
    pub send_errors: bool,
}

impl Default for ICMPServerConfig {
    fn default() -> Self {
        Self {
            versions: [ICMPVersion::V6, ICMPVersion::V4].to_vec(),
            addresses: Vec::new(),
            reply_echo: true,
            send_errors: true,
        }
    }
}

///
pub trait ICMPHandler {
    async fn on_connection(&self, connection: &mut ICMPConnection);
}

#[derive(Debug, Clone, Default)]
pub struct ICMPServer {
    pub config: ICMPServerConfig,
    pub limits: ICMPLimits,
}

impl ICMPServer {
    pub fn new(config: ICMPServerConfig, limits: ICMPLimits) -> Self {
        todo!()
    }

    pub async fn serve<H: ICMPHandler>(&self, handler: H) -> Result<(), ICMPError> {
        todo!()
    }

    pub fn run<H: ICMPHandler>(&self, handler: H, workers: usize) -> Result<(), ICMPError> {
        todo!()
    }
}

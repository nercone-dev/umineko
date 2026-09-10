use alloc::vec::Vec;
use crate::errors::DNSError;
use crate::types::{DNSName, DNSLimits};
use crate::protocol::base::{DNSConnection, DNSTransport};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DNSServerConfig {
    pub transports: Vec<DNSTransport>,
    pub zones: Vec<DNSName>,

    pub recursion: bool,
    pub sign: bool,
    pub cache: bool,
}

impl Default for DNSServerConfig {
    fn default() -> Self {
        Self {
            transports: [DNSTransport::UDP, DNSTransport::TCP].to_vec(),
            zones: Vec::new(),

            recursion: false,
            sign: false,
            cache: true,
        }
    }
}

///
pub trait DNSHandler {
    async fn on_connection(&self, connection: &mut DNSConnection);
}

#[derive(Debug, Clone, Default)]
pub struct DNSServer {
    pub config: DNSServerConfig,
    pub limits: DNSLimits,
}

impl DNSServer {
    pub fn new(config: DNSServerConfig, limits: DNSLimits) -> Self {
        todo!()
    }

    pub async fn serve<H: DNSHandler>(&self, handler: H) -> Result<(), DNSError> {
        todo!()
    }

    pub fn run<H: DNSHandler>(&self, handler: H, workers: usize) -> Result<(), DNSError> {
        todo!()
    }
}

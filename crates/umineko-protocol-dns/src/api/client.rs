use alloc::{string::String, vec::Vec};
use crate::errors::DNSError;
use crate::types::{DNSType, DNSRecord, DNSMessage, DNSLimits};
use crate::protocol::base::{DNSConnection, DNSTransport};
use crate::helpers::resolver::{DNSResolver, DNSResolverMode};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DNSClientConfig {
    pub transports: Vec<DNSTransport>,
    pub servers: Vec<String>,
    pub mode: DNSResolverMode,

    pub validate: bool,
    pub cache: bool,
    pub upgrade_on_truncation: bool,
}

impl Default for DNSClientConfig {
    fn default() -> Self {
        Self {
            transports: [DNSTransport::HTTPS, DNSTransport::TLS, DNSTransport::QUIC, DNSTransport::UDP, DNSTransport::TCP].to_vec(),
            servers: Vec::new(),
            mode: DNSResolverMode::Recursive,

            validate: true,
            cache: true,
            upgrade_on_truncation: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DNSClient {
    pub config: DNSClientConfig,
    pub limits: DNSLimits,
    pub resolver: DNSResolver,
}

impl DNSClient {
    pub fn new(config: DNSClientConfig, limits: DNSLimits) -> Self {
        todo!()
    }

    pub async fn open(&self, transport: DNSTransport, server: &str) -> Result<DNSConnection, DNSError> {
        todo!()
    }

    pub async fn query(&self, message: &DNSMessage) -> Result<DNSMessage, DNSError> {
        todo!()
    }

    pub async fn resolve(&mut self, name: &str, kind: DNSType) -> Result<Vec<DNSRecord>, DNSError> {
        todo!()
    }

    pub async fn resolve_address(&mut self, name: &str) -> Result<Vec<DNSRecord>, DNSError> {
        todo!()
    }

    pub async fn resolve_reverse(&mut self, address: &[u8]) -> Result<Vec<DNSRecord>, DNSError> {
        todo!()
    }
}


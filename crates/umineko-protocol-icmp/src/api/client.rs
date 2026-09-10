use alloc::vec::Vec;
use crate::errors::ICMPError;
use crate::types::{ICMPVersion, ICMPType, ICMPCode, ICMPLimits};
use crate::protocol::base::ICMPConnection;
use crate::provider::{ICMPProviderRequest, ICMPProviders};

use umineko_protocol_ip::IPAddress;
use umineko_helpers::provider::ProviderOpening;

#[derive(Debug, Clone, PartialEq)]
pub struct ICMPClientConfig {
    pub versions: Vec<ICMPVersion>,
    pub hop_limit: u8,
    pub echo_size: usize,
}

impl Default for ICMPClientConfig {
    fn default() -> Self {
        Self {
            versions: [ICMPVersion::V6, ICMPVersion::V4].to_vec(),
            hop_limit: 64,
            echo_size: 56,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ICMPClient {
    pub config: ICMPClientConfig,
    pub limits: ICMPLimits,
}

impl ICMPClient {
    pub fn new(config: ICMPClientConfig, limits: ICMPLimits) -> Self {
        todo!()
    }

    pub async fn open(&self, version: ICMPVersion) -> Result<ICMPConnection, ICMPError> {
        let request = ICMPProviderRequest::Open { version, local: None, remote: None, config: &self.config, limits: &self.limits };
        match ICMPProviders::open(&request)? {
            Some(ProviderOpening { provider, handle }) => ICMPConnection::from_provider(version, provider, handle),
            None => todo!(),
        }
    }

    pub async fn send(&self, destination: IPAddress, kind: ICMPType, code: ICMPCode, payload: &[u8]) -> Result<usize, ICMPError> {
        let mut connection = self.open(ICMPVersion::from_ip_version(destination.version())).await?;
        let sent = connection.send(destination, kind, code, payload).await?;
        connection.close().await?;
        Ok(sent)
    }

    pub async fn ping(&self, destination: IPAddress) -> Result<f64, ICMPError> {
        todo!()
    }

    pub async fn trace(&self, destination: IPAddress, max_hops: u8) -> Result<Vec<(u8, Option<IPAddress>, f64)>, ICMPError> {
        todo!()
    }
}


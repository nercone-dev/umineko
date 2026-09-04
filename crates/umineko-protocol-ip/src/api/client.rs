use alloc::vec::Vec;
use crate::errors::IPError;
use crate::types::{IPVersion, IPAddress, IPProtocol, IPToS, IPLimits};
use crate::helpers::routing::IPRoutingTable;
use crate::protocol::base::IPConnection;
use crate::provider::{IPProviderRequest, IPProviders};
use umineko_helpers::provider::ProviderOpening;

#[derive(Debug, Clone, PartialEq)]
pub struct IPClientConfig {
    pub versions: Vec<IPVersion>,
    pub protocol: IPProtocol,
    pub type_of_service: IPToS,
    pub hop_limit: u8,
    pub fragment: bool,
}

impl Default for IPClientConfig {
    fn default() -> Self {
        Self {
            versions: [IPVersion::V6, IPVersion::V4].to_vec(),
            protocol: IPProtocol::Unknown(255),
            type_of_service: IPToS::default(),
            hop_limit: 64,
            fragment: true,
        }
    }
}

#[derive(Debug)]
pub struct IPClient {
    pub config: IPClientConfig,
    pub limits: IPLimits,
    pub routes: IPRoutingTable,
}

impl Default for IPClient {
    fn default() -> Self {
        todo!()
    }
}

impl IPClient {
    pub fn new(config: IPClientConfig, limits: IPLimits) -> Self {
        todo!()
    }

    pub async fn open(&self, destination: IPAddress) -> Result<IPConnection, IPError> {
        let version = destination.version();
        let request = IPProviderRequest::Open { version, protocol: self.config.protocol, local: None, remote: Some(destination), config: &self.config, limits: &self.limits };
        match IPProviders::open(&request)? {
            Some(ProviderOpening { provider, handle }) => IPConnection::from_provider(version, provider, handle),
            None => todo!(),
        }
    }

    pub async fn send(&self, destination: IPAddress, payload: &[u8]) -> Result<usize, IPError> {
        let mut connection = self.open(destination).await?;
        let sent = connection.send(destination, payload).await?;
        connection.close().await?;
        Ok(sent)
    }
}


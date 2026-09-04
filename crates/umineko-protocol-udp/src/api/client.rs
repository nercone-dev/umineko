use crate::errors::UDPError;
use crate::types::{UDPEndpoint, UDPLimits};
use crate::protocol::connection::{UDPConnection, UDPSocket};
use crate::provider::{UDPProviderRequest, UDPProviders};
use umineko_helpers::provider::ProviderOpening;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UDPClientConfig {
    pub checksum: bool,
    pub fragment: bool,
    pub path_discovery: bool,
    pub multicast_hops: u8,
}

impl Default for UDPClientConfig {
    fn default() -> Self {
        Self { checksum: true, fragment: false, path_discovery: true, multicast_hops: 1 }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct UDPClient {
    pub config: UDPClientConfig,
    pub limits: UDPLimits,
}

impl UDPClient {
    pub fn new(config: UDPClientConfig, limits: UDPLimits) -> Self {
        Self { config, limits }
    }

    pub async fn bind(&self, local: UDPEndpoint) -> Result<UDPSocket, UDPError> {
        UDPSocket::bind_with(local, &self.config, self.limits).await
    }

    pub async fn connect(&self, remote: UDPEndpoint) -> Result<UDPConnection, UDPError> {
        match UDPProviders::open(&UDPProviderRequest::Connect { local: None, remote, config: &self.config, limits: &self.limits })? {
            Some(ProviderOpening { provider, handle }) => UDPConnection::from_provider(provider, handle, self.limits),
            None => todo!(),
        }
    }

    pub async fn send(&self, remote: UDPEndpoint, data: &[u8]) -> Result<usize, UDPError> {
        let mut connection = self.connect(remote).await?;
        let sent = connection.send(data).await?;
        connection.close().await?;
        Ok(sent)
    }
}

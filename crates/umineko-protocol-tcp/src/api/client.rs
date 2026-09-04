use crate::errors::TCPError;
use crate::types::{TCPEndpoint, TCPLimits};
use crate::protocol::connection::TCPConnection;
use crate::provider::{TCPProviderRequest, TCPProviders};
use umineko_helpers::provider::ProviderOpening;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TCPClientConfig {
    pub no_delay: bool,
    pub keepalive: bool,
    pub fast_open: bool,
    pub linger: bool,
}

impl Default for TCPClientConfig {
    fn default() -> Self {
        Self { no_delay: true, keepalive: true, fast_open: false, linger: false }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct TCPClient {
    pub config: TCPClientConfig,
    pub limits: TCPLimits,
}

impl TCPClient {
    pub fn new(config: TCPClientConfig, limits: TCPLimits) -> Self {
        Self { config, limits }
    }

    pub async fn connect(&self, remote: TCPEndpoint) -> Result<TCPConnection, TCPError> {
        self.open(None, remote).await
    }

    pub async fn connect_from(&self, local: TCPEndpoint, remote: TCPEndpoint) -> Result<TCPConnection, TCPError> {
        self.open(Some(local), remote).await
    }

    pub async fn open(&self, local: Option<TCPEndpoint>, remote: TCPEndpoint) -> Result<TCPConnection, TCPError> {
        match TCPProviders::open(&TCPProviderRequest::Connect { local, remote, config: &self.config, limits: &self.limits })? {
            Some(ProviderOpening { provider, handle }) => TCPConnection::from_provider(provider, handle, self.limits),
            None => todo!(),
        }
    }
}

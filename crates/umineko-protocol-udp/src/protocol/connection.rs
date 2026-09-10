use alloc::sync::Arc;
use crate::errors::UDPError;
use crate::types::{UDPEndpoint, UDPLimits};
use crate::api::client::UDPClientConfig;
use crate::provider::{UDPProvider, UDPProviderRequest, UDPProviders};

use umineko_helpers::provider::{ProviderBackend, ProviderHandle, ProviderInterest, ProviderOpening};

#[derive(Debug)]
pub struct UDPSocket {
    local: UDPEndpoint,
    limits: UDPLimits,
    backend: ProviderBackend<dyn UDPProvider>,
}

impl UDPSocket {
    pub async fn bind(local: UDPEndpoint, limits: UDPLimits) -> Result<Self, UDPError> {
        Self::bind_with(local, &UDPClientConfig::default(), limits).await
    }

    pub async fn bind_with(local: UDPEndpoint, config: &UDPClientConfig, limits: UDPLimits) -> Result<Self, UDPError> {
        match UDPProviders::open(&UDPProviderRequest::Bind { local, config, limits: &limits })? {
            Some(ProviderOpening { provider, handle }) => Self::from_provider(provider, handle, limits),
            None => todo!(),
        }
    }

    pub fn from_provider(provider: Arc<dyn UDPProvider>, handle: ProviderHandle, limits: UDPLimits) -> Result<Self, UDPError> {
        let backend = ProviderBackend::Handle { provider: provider.clone(), handle };
        let local = provider.local(handle)?;
        Ok(Self { local, limits, backend })
    }

    pub fn provider(&self) -> Option<&Arc<dyn UDPProvider>> {
        self.backend.provider()
    }

    pub fn local(&self) -> UDPEndpoint {
        self.local
    }

    pub fn limits(&self) -> UDPLimits {
        self.limits
    }

    pub fn mtu(&self) -> usize {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => provider.mtu(*handle).unwrap_or(self.limits.max_datagram_size as usize),
        }
    }

    pub async fn send_to(&mut self, remote: UDPEndpoint, data: &[u8]) -> Result<usize, UDPError> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => Ok(ProviderInterest::Writable.retry(|cx| provider.poll_ready(*handle, ProviderInterest::Writable, cx), || provider.send_to(*handle, remote, data)).await?),
        }
    }

    pub async fn receive_from(&mut self, data: &mut [u8]) -> Result<(usize, UDPEndpoint), UDPError> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => Ok(ProviderInterest::Readable.retry(|cx| provider.poll_ready(*handle, ProviderInterest::Readable, cx), || provider.receive_from(*handle, data)).await?),
        }
    }

    pub async fn connect(self, remote: UDPEndpoint) -> Result<UDPConnection, UDPError> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => provider.connect(*handle, remote)?,
        }
        Ok(UDPConnection { local: self.local, remote, limits: self.limits, backend: self.backend })
    }

    pub async fn close(&mut self) -> Result<(), UDPError> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => Ok(provider.close(*handle)?),
        }
    }
}

#[derive(Debug)]
pub struct UDPConnection {
    local: UDPEndpoint,
    remote: UDPEndpoint,
    limits: UDPLimits,
    backend: ProviderBackend<dyn UDPProvider>,
}

impl UDPConnection {
    pub fn from_provider(provider: Arc<dyn UDPProvider>, handle: ProviderHandle, limits: UDPLimits) -> Result<Self, UDPError> {
        let backend = ProviderBackend::Handle { provider: provider.clone(), handle };
        let local = provider.local(handle)?;
        let remote = provider.remote(handle)?;
        Ok(Self { local, remote, limits, backend })
    }

    pub fn provider(&self) -> Option<&Arc<dyn UDPProvider>> {
        self.backend.provider()
    }

    pub fn local(&self) -> UDPEndpoint {
        self.local
    }

    pub fn remote(&self) -> UDPEndpoint {
        self.remote
    }

    pub fn limits(&self) -> UDPLimits {
        self.limits
    }

    pub fn mtu(&self) -> usize {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => provider.mtu(*handle).unwrap_or(self.limits.max_datagram_size as usize),
        }
    }

    pub async fn send(&mut self, data: &[u8]) -> Result<usize, UDPError> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => Ok(ProviderInterest::Writable.retry(|cx| provider.poll_ready(*handle, ProviderInterest::Writable, cx), || provider.send(*handle, data)).await?),
        }
    }

    pub async fn receive(&mut self, data: &mut [u8]) -> Result<usize, UDPError> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => Ok(ProviderInterest::Readable.retry(|cx| provider.poll_ready(*handle, ProviderInterest::Readable, cx), || provider.receive(*handle, data)).await?),
        }
    }

    pub async fn close(&mut self) -> Result<(), UDPError> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => Ok(provider.close(*handle)?),
        }
    }
}

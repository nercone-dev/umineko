use alloc::sync::Arc;
use crate::errors::TCPError;
use crate::types::{TCPEndpoint, TCPState, TCPLimits};
use crate::helpers::congestion::TCPCongestion;
use crate::api::server::TCPServerConfig;
use crate::provider::{TCPProvider, TCPProviderRequest, TCPProviders};

use umineko_helpers::provider::{ProviderBackend, ProviderHandle, ProviderInterest, ProviderOpening};

#[derive(Debug)]
pub struct TCPConnection {
    local: TCPEndpoint,
    remote: TCPEndpoint,
    state: TCPState,
    limits: TCPLimits,
    congestion: Option<TCPCongestion>,
    backend: ProviderBackend<dyn TCPProvider>,
}

impl TCPConnection {
    pub fn from_provider(provider: Arc<dyn TCPProvider>, handle: ProviderHandle, limits: TCPLimits) -> Result<Self, TCPError> {
        let backend = ProviderBackend::Handle { provider: provider.clone(), handle };
        let local = provider.local(handle)?;
        let remote = provider.remote(handle)?;
        let state = provider.state(handle)?;
        Ok(Self { local, remote, state, limits, congestion: None, backend })
    }

    pub fn provider(&self) -> Option<&Arc<dyn TCPProvider>> {
        self.backend.provider()
    }

    pub fn local(&self) -> TCPEndpoint {
        self.local
    }

    pub fn remote(&self) -> TCPEndpoint {
        self.remote
    }

    pub fn state(&self) -> TCPState {
        match &self.backend {
            ProviderBackend::Builtin => self.state,
            ProviderBackend::Handle { provider, handle } => provider.state(*handle).unwrap_or(self.state),
        }
    }

    pub fn limits(&self) -> TCPLimits {
        self.limits
    }

    pub fn segment_size(&self) -> u16 {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => provider.segment_size(*handle).unwrap_or(self.limits.max_segment_size),
        }
    }

    pub fn set_no_delay(&mut self, no_delay: bool) -> Result<(), TCPError> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => Ok(provider.set_no_delay(*handle, no_delay)?),
        }
    }

    pub fn set_keepalive(&mut self, keepalive: bool) -> Result<(), TCPError> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => Ok(provider.set_keepalive(*handle, keepalive)?),
        }
    }

    pub async fn send(&mut self, data: &[u8]) -> Result<usize, TCPError> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => Ok(ProviderInterest::Writable.retry(|cx| provider.poll_ready(*handle, ProviderInterest::Writable, cx), || provider.send(*handle, data)).await?),
        }
    }

    pub async fn receive(&mut self, data: &mut [u8]) -> Result<usize, TCPError> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => Ok(ProviderInterest::Readable.retry(|cx| provider.poll_ready(*handle, ProviderInterest::Readable, cx), || provider.receive(*handle, data)).await?),
        }
    }

    pub async fn shutdown(&mut self) -> Result<(), TCPError> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => Ok(provider.shutdown(*handle)?),
        }
    }

    pub async fn close(&mut self) -> Result<(), TCPError> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => {
                provider.close(*handle)?;
                self.state = TCPState::Closed;
                Ok(())
            }
        }
    }

    pub async fn reset(&mut self) -> Result<(), TCPError> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => {
                provider.reset(*handle)?;
                self.state = TCPState::Closed;
                Ok(())
            }
        }
    }
}

#[derive(Debug)]
pub struct TCPListener {
    local: TCPEndpoint,
    backlog: u32,
    limits: TCPLimits,
    backend: ProviderBackend<dyn TCPProvider>,
}

impl TCPListener {
    pub async fn bind(local: TCPEndpoint, backlog: u32, limits: TCPLimits) -> Result<Self, TCPError> {
        Self::bind_with(local, &TCPServerConfig { backlog, ..TCPServerConfig::default() }, limits).await
    }

    pub async fn bind_with(local: TCPEndpoint, config: &TCPServerConfig, limits: TCPLimits) -> Result<Self, TCPError> {
        match TCPProviders::open(&TCPProviderRequest::Bind { local, config, limits: &limits })? {
            Some(ProviderOpening { provider, handle }) => Self::from_provider(provider, handle, config.backlog, limits),
            None => todo!(),
        }
    }

    pub fn from_provider(provider: Arc<dyn TCPProvider>, handle: ProviderHandle, backlog: u32, limits: TCPLimits) -> Result<Self, TCPError> {
        let backend = ProviderBackend::Handle { provider: provider.clone(), handle };
        let local = provider.local(handle)?;
        Ok(Self { local, backlog, limits, backend })
    }

    pub fn provider(&self) -> Option<&Arc<dyn TCPProvider>> {
        self.backend.provider()
    }

    pub fn local(&self) -> TCPEndpoint {
        self.local
    }

    pub fn backlog(&self) -> u32 {
        self.backlog
    }

    pub fn limits(&self) -> TCPLimits {
        self.limits
    }

    pub async fn accept(&mut self) -> Result<TCPConnection, TCPError> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => {
                let accepted = ProviderInterest::Readable.retry(|cx| provider.poll_ready(*handle, ProviderInterest::Readable, cx), || provider.accept(*handle)).await?;
                TCPConnection::from_provider(provider.clone(), accepted, self.limits)
            }
        }
    }

    pub async fn close(&mut self) -> Result<(), TCPError> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => Ok(provider.close(*handle)?),
        }
    }
}

use alloc::sync::Arc;
use crate::errors::UDSError;
use crate::types::{UDSPath, UDSType, UDSLimits};
use crate::helpers::ancillary::UDSAncillary;
use crate::helpers::credentials::UDSCredentials;
use crate::api::client::UDSClientConfig;
use crate::api::server::UDSServerConfig;
use crate::provider::{UDSProvider, UDSProviderRequest, UDSProviders};

use umineko_helpers::provider::{ProviderBackend, ProviderHandle, ProviderInterest, ProviderOpening};

#[derive(Debug)]
pub struct UDSStreamConnection {
    local: UDSPath,
    remote: UDSPath,
    limits: UDSLimits,
    backend: ProviderBackend<dyn UDSProvider>,
}

impl UDSStreamConnection {
    pub const KIND: UDSType = UDSType::Stream;

    pub async fn connect(remote: UDSPath, limits: UDSLimits) -> Result<Self, UDSError> {
        Self::connect_with(remote, &UDSClientConfig { kind: Self::KIND, ..UDSClientConfig::default() }, limits).await
    }

    pub async fn connect_with(remote: UDSPath, config: &UDSClientConfig, limits: UDSLimits) -> Result<Self, UDSError> {
        match UDSProviders::open(&UDSProviderRequest::Connect { kind: Self::KIND, remote: &remote, config, limits: &limits })? {
            Some(ProviderOpening { provider, handle }) => Self::from_provider(provider, handle, limits),
            None => todo!(),
        }
    }

    pub fn from_provider(provider: Arc<dyn UDSProvider>, handle: ProviderHandle, limits: UDSLimits) -> Result<Self, UDSError> {
        let backend = ProviderBackend::Handle { provider: provider.clone(), handle };
        let local = provider.local(handle)?;
        let remote = provider.remote(handle)?;
        Ok(Self { local, remote, limits, backend })
    }

    pub fn provider(&self) -> Option<&Arc<dyn UDSProvider>> {
        self.backend.provider()
    }

    pub fn kind(&self) -> UDSType {
        Self::KIND
    }

    pub fn local(&self) -> &UDSPath {
        &self.local
    }

    pub fn remote(&self) -> &UDSPath {
        &self.remote
    }

    pub fn limits(&self) -> UDSLimits {
        self.limits
    }

    pub fn credentials(&self) -> Result<UDSCredentials, UDSError> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => Ok(provider.credentials(*handle)?),
        }
    }

    pub async fn send(&mut self, data: &[u8]) -> Result<usize, UDSError> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => Ok(ProviderInterest::Writable.retry(|cx| provider.poll_ready(*handle, ProviderInterest::Writable, cx), || provider.send(*handle, data)).await?),
        }
    }

    pub async fn receive(&mut self, data: &mut [u8]) -> Result<usize, UDSError> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => Ok(ProviderInterest::Readable.retry(|cx| provider.poll_ready(*handle, ProviderInterest::Readable, cx), || provider.receive(*handle, data)).await?),
        }
    }

    pub async fn send_with(&mut self, data: &[u8], ancillary: &UDSAncillary) -> Result<usize, UDSError> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => Ok(ProviderInterest::Writable.retry(|cx| provider.poll_ready(*handle, ProviderInterest::Writable, cx), || provider.send_with(*handle, data, ancillary)).await?),
        }
    }

    pub async fn receive_with(&mut self, data: &mut [u8]) -> Result<(usize, UDSAncillary), UDSError> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => Ok(ProviderInterest::Readable.retry(|cx| provider.poll_ready(*handle, ProviderInterest::Readable, cx), || provider.receive_with(*handle, data)).await?),
        }
    }

    pub async fn shutdown(&mut self) -> Result<(), UDSError> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => Ok(provider.shutdown(*handle)?),
        }
    }

    pub async fn close(&mut self) -> Result<(), UDSError> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => Ok(provider.close(*handle)?),
        }
    }
}

#[derive(Debug)]
pub struct UDSStreamListener {
    local: UDSPath,
    backlog: u32,
    limits: UDSLimits,
    backend: ProviderBackend<dyn UDSProvider>,
}

impl UDSStreamListener {
    pub const KIND: UDSType = UDSType::Stream;

    pub async fn bind(local: UDSPath, backlog: u32, limits: UDSLimits) -> Result<Self, UDSError> {
        Self::bind_with(local, &UDSServerConfig { kind: Self::KIND, backlog, ..UDSServerConfig::default() }, limits).await
    }

    pub async fn bind_with(local: UDSPath, config: &UDSServerConfig, limits: UDSLimits) -> Result<Self, UDSError> {
        match UDSProviders::open(&UDSProviderRequest::Bind { kind: Self::KIND, local: &local, config, limits: &limits })? {
            Some(ProviderOpening { provider, handle }) => Self::from_provider(provider, handle, config.backlog, limits),
            None => todo!(),
        }
    }

    pub fn from_provider(provider: Arc<dyn UDSProvider>, handle: ProviderHandle, backlog: u32, limits: UDSLimits) -> Result<Self, UDSError> {
        let backend = ProviderBackend::Handle { provider: provider.clone(), handle };
        let local = provider.local(handle)?;
        Ok(Self { local, backlog, limits, backend })
    }

    pub fn provider(&self) -> Option<&Arc<dyn UDSProvider>> {
        self.backend.provider()
    }

    pub fn kind(&self) -> UDSType {
        Self::KIND
    }

    pub fn local(&self) -> &UDSPath {
        &self.local
    }

    pub fn backlog(&self) -> u32 {
        self.backlog
    }

    pub fn limits(&self) -> UDSLimits {
        self.limits
    }

    pub async fn accept(&mut self) -> Result<UDSStreamConnection, UDSError> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => {
                let accepted = ProviderInterest::Readable.retry(|cx| provider.poll_ready(*handle, ProviderInterest::Readable, cx), || provider.accept(*handle)).await?;
                UDSStreamConnection::from_provider(provider.clone(), accepted, self.limits)
            }
        }
    }

    pub async fn close(&mut self) -> Result<(), UDSError> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => Ok(provider.close(*handle)?),
        }
    }
}

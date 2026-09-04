use alloc::{string::String, sync::Arc, vec::Vec};
use crate::errors::{QUICError, QUICTransportError};
use crate::types::{QUICVersion, QUICRole, QUICConnectionID, QUICStreamID, QUICTransportParameters, QUICLimits};
use crate::protocol::stream::QUICStream;
use crate::helpers::congestion::QUICCongestion;
use crate::helpers::loss::QUICLossDetection;
use crate::helpers::handshake::QUICHandshake;
use crate::provider::QUICProvider;

use umineko_helpers::provider::{ProviderBackend, ProviderError, ProviderHandle};

#[derive(Debug)]
pub struct QUICV2Connection {
    role: QUICRole,
    local: QUICConnectionID,
    remote: QUICConnectionID,
    parameters: QUICTransportParameters,
    handshake: Option<QUICHandshake>,
    congestion: Option<QUICCongestion>,
    loss: Option<QUICLossDetection>,
    application_protocol: Option<String>,
    limits: QUICLimits,
    backend: ProviderBackend<dyn QUICProvider>,
}

impl QUICV2Connection {
    pub const VERSION: QUICVersion = QUICVersion::V2;

    pub fn new(role: QUICRole, limits: QUICLimits) -> Self {
        todo!()
    }

    pub fn from_provider(provider: Arc<dyn QUICProvider>, handle: ProviderHandle, limits: QUICLimits) -> Result<Self, QUICError> {
        let backend = ProviderBackend::Handle { provider: provider.clone(), handle };
        if provider.version(handle)? != Self::VERSION {
            return Err(QUICError::Version);
        }
        let role = provider.role(handle)?;
        let local = provider.local_id(handle)?;
        let remote = provider.remote_id(handle)?;
        let parameters = provider.parameters(handle)?;
        let application_protocol = provider.application_protocol(handle)?;
        Ok(Self { role, local, remote, parameters, handshake: None, congestion: None, loss: None, application_protocol, limits, backend })
    }

    pub fn provider(&self) -> Option<&Arc<dyn QUICProvider>> {
        self.backend.provider()
    }

    pub fn synchronize(&mut self) -> Result<(), QUICError> {
        if let ProviderBackend::Handle { provider, handle } = &self.backend {
            self.remote = provider.remote_id(*handle)?;
            self.parameters = provider.parameters(*handle)?;
            self.application_protocol = provider.application_protocol(*handle)?;
        }
        Ok(())
    }

    pub fn version(&self) -> QUICVersion {
        Self::VERSION
    }

    pub fn role(&self) -> QUICRole {
        self.role
    }

    pub fn local_id(&self) -> &QUICConnectionID {
        &self.local
    }

    pub fn remote_id(&self) -> &QUICConnectionID {
        &self.remote
    }

    pub fn parameters(&self) -> &QUICTransportParameters {
        &self.parameters
    }

    pub fn limits(&self) -> QUICLimits {
        self.limits
    }

    pub fn application_protocol(&self) -> Option<&str> {
        self.application_protocol.as_deref()
    }

    pub fn established(&self) -> bool {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => provider.established(*handle).unwrap_or(false),
        }
    }

    pub fn absorb(&mut self, datagram: &[u8]) -> Result<(), QUICError> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => Ok(provider.absorb(*handle, datagram)?),
        }
    }

    pub fn emit(&mut self, output: &mut Vec<u8>) -> Result<usize, QUICError> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => Ok(provider.emit(*handle, output)?),
        }
    }

    pub fn timeout(&self) -> Result<Option<f64>, QUICError> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => Ok(provider.timeout(*handle)?),
        }
    }

    pub fn step(&mut self) -> Result<bool, QUICError> {
        let established = match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => provider.handshake(*handle)?,
        };
        if established {
            self.synchronize()?;
        }
        Ok(established)
    }

    pub async fn handshake(&mut self) -> Result<(), QUICError> {
        match self.step()? {
            true => Ok(()),
            false => Err(QUICError::Provider(ProviderError::WouldBlock)),
        }
    }

    pub async fn open(&mut self, bidirectional: bool) -> Result<QUICStream, QUICError> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => QUICStream::from_provider(provider.clone(), provider.open_stream(*handle, bidirectional)?, self.limits),
        }
    }

    pub async fn accept(&mut self) -> Result<QUICStream, QUICError> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => QUICStream::from_provider(provider.clone(), provider.accept_stream(*handle)?, self.limits),
        }
    }

    pub fn stream(&mut self, id: QUICStreamID) -> Option<&mut QUICStream> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { .. } => {
                let _ = id;
                None
            }
        }
    }

    pub async fn probe(&mut self) -> Result<(), QUICError> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => Ok(provider.probe(*handle)?),
        }
    }

    pub async fn migrate(&mut self) -> Result<(), QUICError> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => Ok(provider.migrate(*handle)?),
        }
    }

    pub async fn refresh(&mut self) -> Result<(), QUICError> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => Ok(provider.refresh(*handle)?),
        }
    }

    pub async fn close(&mut self, error: QUICTransportError, reason: &[u8]) -> Result<(), QUICError> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => Ok(provider.close(*handle, error, reason)?),
        }
    }

    pub fn supported_versions() -> Vec<QUICVersion> {
        todo!()
    }
}

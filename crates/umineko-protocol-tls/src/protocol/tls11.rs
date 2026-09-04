use alloc::{string::String, sync::Arc, vec::Vec};
use crate::errors::{TLSError, TLSAlert};
use crate::types::{TLSVersion, TLSRole, TLSGroup, TLSCipher, TLSLimits};
use crate::helpers::certificate::TLSCertificateChain;
use crate::helpers::alpn::TLSApplicationProtocol;
use crate::helpers::handshake::TLSHandshakeState;
use crate::helpers::key_schedule::TLSKeySchedule;
use crate::provider::TLSProvider;

use umineko_helpers::provider::{ProviderBackend, ProviderError, ProviderHandle};

#[derive(Debug)]
pub struct TLS11Connection {
    role: TLSRole,
    state: TLSHandshakeState,
    cipher: Option<TLSCipher>,
    group: Option<TLSGroup>,
    schedule: Option<TLSKeySchedule>,
    application_protocol: Option<String>,
    server_name: Option<String>,
    peer_certificates: Option<TLSCertificateChain>,
    resumed: bool,
    limits: TLSLimits,
    backend: ProviderBackend<dyn TLSProvider>,
}

impl TLS11Connection {
    pub const VERSION: TLSVersion = TLSVersion::V1_1;

    pub fn new(role: TLSRole, limits: TLSLimits) -> Self {
        todo!()
    }

    pub fn from_provider(provider: Arc<dyn TLSProvider>, handle: ProviderHandle, limits: TLSLimits) -> Result<Self, TLSError> {
        let backend = ProviderBackend::Handle { provider: provider.clone(), handle };
        let role = provider.role(handle)?;
        let mut connection = Self { role, state: TLSHandshakeState::Initial, cipher: None, group: None, schedule: None, application_protocol: None, server_name: None, peer_certificates: None, resumed: false, limits, backend };
        connection.synchronize()?;
        Ok(connection)
    }

    pub fn provider(&self) -> Option<&Arc<dyn TLSProvider>> {
        self.backend.provider()
    }

    pub fn synchronize(&mut self) -> Result<(), TLSError> {
        if let ProviderBackend::Handle { provider, handle } = &self.backend {
            if provider.version(*handle)?.is_some_and(|version| version != Self::VERSION) {
                return Err(TLSError::Version);
            }
            self.state = provider.state(*handle)?;
            self.cipher = provider.cipher(*handle)?;
            self.group = provider.group(*handle)?;
            self.application_protocol = provider.application_protocol(*handle)?;
            self.server_name = provider.server_name(*handle)?;
            self.peer_certificates = provider.peer_certificates(*handle)?;
            self.resumed = provider.resumed(*handle)?;
        }
        Ok(())
    }

    pub fn version(&self) -> TLSVersion {
        Self::VERSION
    }

    pub fn role(&self) -> TLSRole {
        self.role
    }

    pub fn state(&self) -> TLSHandshakeState {
        self.state
    }

    pub fn cipher(&self) -> Option<TLSCipher> {
        self.cipher
    }

    pub fn group(&self) -> Option<TLSGroup> {
        self.group
    }

    pub fn limits(&self) -> TLSLimits {
        self.limits
    }

    pub fn peer_certificates(&self) -> Option<&TLSCertificateChain> {
        self.peer_certificates.as_ref()
    }

    pub fn application_protocol(&self) -> Option<&str> {
        self.application_protocol.as_deref()
    }

    pub fn server_name(&self) -> Option<&str> {
        self.server_name.as_deref()
    }

    pub fn resumed(&self) -> bool {
        self.resumed
    }

    pub fn select_certificate(&mut self, chain: TLSCertificateChain) -> Result<(), TLSError> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => Ok(provider.select_certificate(*handle, &chain)?),
        }
    }

    pub fn select_application_protocol(&mut self, protocol: TLSApplicationProtocol) -> Result<(), TLSError> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => Ok(provider.select_application_protocol(*handle, &protocol)?),
        }
    }

    pub fn absorb(&mut self, data: &[u8]) -> Result<usize, TLSError> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => Ok(provider.absorb(*handle, data)?),
        }
    }

    pub fn emit(&mut self, output: &mut Vec<u8>) -> Result<usize, TLSError> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => Ok(provider.emit(*handle, output)?),
        }
    }

    pub fn step(&mut self) -> Result<TLSHandshakeState, TLSError> {
        let state = match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => provider.handshake(*handle)?,
        };
        self.state = state;
        if state.established() {
            self.synchronize()?;
        }
        Ok(state)
    }

    pub async fn handshake(&mut self) -> Result<(), TLSError> {
        match self.step()? {
            TLSHandshakeState::Established => Ok(()),
            TLSHandshakeState::Failed | TLSHandshakeState::Closed => Err(TLSError::Handshake),
            _ => Err(TLSError::Provider(ProviderError::WouldBlock)),
        }
    }

    pub async fn send(&mut self, data: &[u8]) -> Result<usize, TLSError> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => Ok(provider.send(*handle, data)?),
        }
    }

    pub async fn receive(&mut self, data: &mut [u8]) -> Result<usize, TLSError> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => Ok(provider.receive(*handle, data)?),
        }
    }

    pub async fn refresh(&mut self) -> Result<(), TLSError> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => Ok(provider.refresh(*handle)?),
        }
    }

    pub async fn alert(&mut self, alert: TLSAlert) -> Result<(), TLSError> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => Ok(provider.alert(*handle, alert)?),
        }
    }

    pub async fn close(&mut self) -> Result<(), TLSError> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => {
                provider.close(*handle)?;
                self.state = TLSHandshakeState::Closed;
                Ok(())
            }
        }
    }
}

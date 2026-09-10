use alloc::sync::Arc;
use crate::errors::QUICError;
use crate::types::{QUICStreamID, QUICLimits};
use crate::helpers::flow::QUICFlowControl;
use crate::provider::QUICProvider;

use umineko_helpers::provider::{ProviderBackend, ProviderHandle};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QUICStreamKind {
    ClientBidirectional,
    ServerBidirectional,
    ClientUnidirectional,
    ServerUnidirectional,
}

impl QUICStreamKind {
    pub fn bidirectional(&self) -> bool {
        matches!(self, Self::ClientBidirectional | Self::ServerBidirectional)
    }

    pub fn from_id(id: QUICStreamID) -> Self {
        match (id.client_initiated(), id.bidirectional()) {
            (true, true) => Self::ClientBidirectional,
            (false, true) => Self::ServerBidirectional,
            (true, false) => Self::ClientUnidirectional,
            (false, false) => Self::ServerUnidirectional,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QUICStreamState {
    Idle,
    Open,
    HalfClosedLocal,
    HalfClosedRemote,
    Closed,
    Reset,
}

impl QUICStreamState {
    pub fn sendable(&self) -> bool {
        matches!(self, Self::Open | Self::HalfClosedRemote)
    }

    pub fn receivable(&self) -> bool {
        matches!(self, Self::Open | Self::HalfClosedLocal)
    }

    pub fn terminal(&self) -> bool {
        matches!(self, Self::Closed | Self::Reset)
    }
}

#[derive(Debug)]
pub struct QUICStream {
    id: QUICStreamID,
    state: QUICStreamState,
    flow: Option<QUICFlowControl>,
    limits: QUICLimits,
    backend: ProviderBackend<dyn QUICProvider>,
}

impl QUICStream {
    pub fn from_provider(provider: Arc<dyn QUICProvider>, handle: ProviderHandle, limits: QUICLimits) -> Result<Self, QUICError> {
        let backend = ProviderBackend::Handle { provider: provider.clone(), handle };
        let id = provider.stream_id(handle)?;
        let state = provider.stream_state(handle)?;
        Ok(Self { id, state, flow: None, limits, backend })
    }

    pub fn provider(&self) -> Option<&Arc<dyn QUICProvider>> {
        self.backend.provider()
    }

    pub fn id(&self) -> QUICStreamID {
        self.id
    }

    pub fn kind(&self) -> QUICStreamKind {
        QUICStreamKind::from_id(self.id)
    }

    pub fn state(&self) -> QUICStreamState {
        match &self.backend {
            ProviderBackend::Builtin => self.state,
            ProviderBackend::Handle { provider, handle } => provider.stream_state(*handle).unwrap_or(self.state),
        }
    }

    pub fn limits(&self) -> QUICLimits {
        self.limits
    }

    pub async fn send(&mut self, data: &[u8]) -> Result<usize, QUICError> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => Ok(provider.stream_send(*handle, data)?),
        }
    }

    pub async fn receive(&mut self, data: &mut [u8]) -> Result<usize, QUICError> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => Ok(provider.stream_receive(*handle, data)?),
        }
    }

    pub async fn finish(&mut self) -> Result<(), QUICError> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => Ok(provider.stream_finish(*handle)?),
        }
    }

    pub async fn reset(&mut self, error: u64) -> Result<(), QUICError> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => Ok(provider.stream_reset(*handle, error)?),
        }
    }

    pub async fn stop(&mut self, error: u64) -> Result<(), QUICError> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => Ok(provider.stream_stop(*handle, error)?),
        }
    }
}

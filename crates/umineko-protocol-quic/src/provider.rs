use alloc::{string::String, vec::Vec};
use crate::errors::QUICTransportError;
use crate::types::{QUICVersion, QUICRole, QUICConnectionID, QUICStreamID, QUICTransportParameters, QUICLimits};
use crate::protocol::stream::QUICStreamState;
use crate::api::client::QUICClientConfig;
use crate::api::server::QUICServerConfig;

use umineko_helpers::provider::{Provider, ProviderError, ProviderHandle, ProviderOpening, ProviderRegistry};

#[derive(Debug, Clone, Copy)]
pub enum QUICProviderRequest<'a> {
    Client { name: &'a str, config: &'a QUICClientConfig, limits: &'a QUICLimits },
    Server { config: &'a QUICServerConfig, limits: &'a QUICLimits },
}

impl QUICProviderRequest<'_> {
    pub fn role(&self) -> QUICRole {
        match self {
            Self::Client { .. } => QUICRole::Client,
            Self::Server { .. } => QUICRole::Server,
        }
    }

    pub fn limits(&self) -> &QUICLimits {
        match self {
            Self::Client { limits, .. } => limits,
            Self::Server { limits, .. } => limits,
        }
    }
}

pub trait QUICProvider: Provider {
    fn supports(&self, request: &QUICProviderRequest<'_>) -> bool;

    fn open(&self, request: &QUICProviderRequest<'_>) -> Result<ProviderHandle, ProviderError>;

    fn absorb(&self, handle: ProviderHandle, datagram: &[u8]) -> Result<(), ProviderError>;

    fn emit(&self, handle: ProviderHandle, output: &mut Vec<u8>) -> Result<usize, ProviderError>;

    fn timeout(&self, handle: ProviderHandle) -> Result<Option<f64>, ProviderError>;

    fn handshake(&self, handle: ProviderHandle) -> Result<bool, ProviderError>;

    fn open_stream(&self, handle: ProviderHandle, bidirectional: bool) -> Result<ProviderHandle, ProviderError>;

    fn accept_stream(&self, handle: ProviderHandle) -> Result<ProviderHandle, ProviderError>;

    fn stream_id(&self, stream: ProviderHandle) -> Result<QUICStreamID, ProviderError>;

    fn stream_state(&self, stream: ProviderHandle) -> Result<QUICStreamState, ProviderError>;

    fn stream_send(&self, stream: ProviderHandle, data: &[u8]) -> Result<usize, ProviderError>;

    fn stream_receive(&self, stream: ProviderHandle, data: &mut [u8]) -> Result<usize, ProviderError>;

    fn stream_finish(&self, stream: ProviderHandle) -> Result<(), ProviderError>;

    fn stream_reset(&self, stream: ProviderHandle, error: u64) -> Result<(), ProviderError>;

    fn stream_stop(&self, stream: ProviderHandle, error: u64) -> Result<(), ProviderError>;

    fn probe(&self, handle: ProviderHandle) -> Result<(), ProviderError>;

    fn migrate(&self, handle: ProviderHandle) -> Result<(), ProviderError>;

    fn refresh(&self, handle: ProviderHandle) -> Result<(), ProviderError>;

    fn close(&self, handle: ProviderHandle, error: QUICTransportError, reason: &[u8]) -> Result<(), ProviderError>;

    fn version(&self, handle: ProviderHandle) -> Result<QUICVersion, ProviderError>;

    fn role(&self, handle: ProviderHandle) -> Result<QUICRole, ProviderError>;

    fn local_id(&self, handle: ProviderHandle) -> Result<QUICConnectionID, ProviderError>;

    fn remote_id(&self, handle: ProviderHandle) -> Result<QUICConnectionID, ProviderError>;

    fn parameters(&self, handle: ProviderHandle) -> Result<QUICTransportParameters, ProviderError>;

    fn application_protocol(&self, handle: ProviderHandle) -> Result<Option<String>, ProviderError>;

    fn established(&self, handle: ProviderHandle) -> Result<bool, ProviderError>;
}

pub struct QUICProviders;

impl QUICProviders {
    pub fn global() -> &'static ProviderRegistry<dyn QUICProvider> {
        static REGISTRY: ProviderRegistry<dyn QUICProvider> = ProviderRegistry::new();
        &REGISTRY
    }

    pub fn open(request: &QUICProviderRequest<'_>) -> Result<Option<ProviderOpening<dyn QUICProvider>>, ProviderError> {
        Self::global().select(|provider| provider.supports(request)).open(|provider| provider.open(request))
    }
}

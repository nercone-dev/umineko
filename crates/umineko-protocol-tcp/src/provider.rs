use core::task::{Context, Poll};
use crate::types::{TCPEndpoint, TCPState, TCPLimits};
use crate::api::client::TCPClientConfig;
use crate::api::server::TCPServerConfig;

use umineko_helpers::provider::{Provider, ProviderError, ProviderHandle, ProviderInterest, ProviderOpening, ProviderRegistry};

#[derive(Debug, Clone, Copy)]
pub enum TCPProviderRequest<'a> {
    Connect { local: Option<TCPEndpoint>, remote: TCPEndpoint, config: &'a TCPClientConfig, limits: &'a TCPLimits },
    Bind { local: TCPEndpoint, config: &'a TCPServerConfig, limits: &'a TCPLimits },
}

impl TCPProviderRequest<'_> {
    pub fn limits(&self) -> &TCPLimits {
        match self {
            Self::Connect { limits, .. } => limits,
            Self::Bind { limits, .. } => limits,
        }
    }
}

pub trait TCPProvider: Provider {
    fn supports(&self, request: &TCPProviderRequest<'_>) -> bool;

    fn open(&self, request: &TCPProviderRequest<'_>) -> Result<ProviderHandle, ProviderError>;

    fn poll_ready(&self, handle: ProviderHandle, interest: ProviderInterest, cx: &mut Context<'_>) -> Poll<Result<(), ProviderError>>;

    fn accept(&self, handle: ProviderHandle) -> Result<ProviderHandle, ProviderError>;

    fn send(&self, handle: ProviderHandle, data: &[u8]) -> Result<usize, ProviderError>;

    fn receive(&self, handle: ProviderHandle, data: &mut [u8]) -> Result<usize, ProviderError>;

    fn shutdown(&self, handle: ProviderHandle) -> Result<(), ProviderError>;

    fn reset(&self, handle: ProviderHandle) -> Result<(), ProviderError>;

    fn close(&self, handle: ProviderHandle) -> Result<(), ProviderError>;

    fn set_no_delay(&self, handle: ProviderHandle, no_delay: bool) -> Result<(), ProviderError>;

    fn set_keepalive(&self, handle: ProviderHandle, keepalive: bool) -> Result<(), ProviderError>;

    fn local(&self, handle: ProviderHandle) -> Result<TCPEndpoint, ProviderError>;

    fn remote(&self, handle: ProviderHandle) -> Result<TCPEndpoint, ProviderError>;

    fn state(&self, handle: ProviderHandle) -> Result<TCPState, ProviderError>;

    fn segment_size(&self, handle: ProviderHandle) -> Result<u16, ProviderError>;
}

pub struct TCPProviders;

impl TCPProviders {
    pub fn global() -> &'static ProviderRegistry<dyn TCPProvider> {
        static REGISTRY: ProviderRegistry<dyn TCPProvider> = ProviderRegistry::new();
        &REGISTRY
    }

    pub fn open(request: &TCPProviderRequest<'_>) -> Result<Option<ProviderOpening<dyn TCPProvider>>, ProviderError> {
        Self::global().select(|provider| provider.supports(request)).open(|provider| provider.open(request))
    }
}

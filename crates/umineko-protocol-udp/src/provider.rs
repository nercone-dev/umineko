use core::task::{Context, Poll};
use crate::types::{UDPEndpoint, UDPLimits};
use crate::api::client::UDPClientConfig;
use crate::api::server::UDPServerConfig;

use umineko_helpers::provider::{Provider, ProviderError, ProviderHandle, ProviderInterest, ProviderOpening, ProviderRegistry};

#[derive(Debug, Clone, Copy)]
pub enum UDPProviderRequest<'a> {
    Bind { local: UDPEndpoint, config: &'a UDPClientConfig, limits: &'a UDPLimits },
    Connect { local: Option<UDPEndpoint>, remote: UDPEndpoint, config: &'a UDPClientConfig, limits: &'a UDPLimits },
    Serve { local: UDPEndpoint, config: &'a UDPServerConfig, limits: &'a UDPLimits },
}

impl UDPProviderRequest<'_> {
    pub fn limits(&self) -> &UDPLimits {
        match self {
            Self::Bind { limits, .. } => limits,
            Self::Connect { limits, .. } => limits,
            Self::Serve { limits, .. } => limits,
        }
    }
}

pub trait UDPProvider: Provider {
    fn supports(&self, request: &UDPProviderRequest<'_>) -> bool;

    fn open(&self, request: &UDPProviderRequest<'_>) -> Result<ProviderHandle, ProviderError>;

    fn poll_ready(&self, handle: ProviderHandle, interest: ProviderInterest, cx: &mut Context<'_>) -> Poll<Result<(), ProviderError>>;

    fn connect(&self, handle: ProviderHandle, remote: UDPEndpoint) -> Result<(), ProviderError>;

    fn send_to(&self, handle: ProviderHandle, remote: UDPEndpoint, data: &[u8]) -> Result<usize, ProviderError>;

    fn receive_from(&self, handle: ProviderHandle, data: &mut [u8]) -> Result<(usize, UDPEndpoint), ProviderError>;

    fn send(&self, handle: ProviderHandle, data: &[u8]) -> Result<usize, ProviderError>;

    fn receive(&self, handle: ProviderHandle, data: &mut [u8]) -> Result<usize, ProviderError>;

    fn close(&self, handle: ProviderHandle) -> Result<(), ProviderError>;

    fn local(&self, handle: ProviderHandle) -> Result<UDPEndpoint, ProviderError>;

    fn remote(&self, handle: ProviderHandle) -> Result<UDPEndpoint, ProviderError>;

    fn mtu(&self, handle: ProviderHandle) -> Result<usize, ProviderError>;
}

pub struct UDPProviders;

impl UDPProviders {
    pub fn global() -> &'static ProviderRegistry<dyn UDPProvider> {
        static REGISTRY: ProviderRegistry<dyn UDPProvider> = ProviderRegistry::new();
        &REGISTRY
    }

    pub fn open(request: &UDPProviderRequest<'_>) -> Result<Option<ProviderOpening<dyn UDPProvider>>, ProviderError> {
        Self::global().select(|provider| provider.supports(request)).open(|provider| provider.open(request))
    }
}

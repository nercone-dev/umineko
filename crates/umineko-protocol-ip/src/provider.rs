use core::task::{Context, Poll};
use crate::types::{IPVersion, IPAddress, IPProtocol, IPLimits};
use crate::api::client::IPClientConfig;
use crate::api::server::IPServerConfig;

use umineko_helpers::provider::{Provider, ProviderError, ProviderHandle, ProviderInterest, ProviderOpening, ProviderRegistry};

#[derive(Debug, Clone, Copy)]
pub enum IPProviderRequest<'a> {
    Open { version: IPVersion, protocol: IPProtocol, local: Option<IPAddress>, remote: Option<IPAddress>, config: &'a IPClientConfig, limits: &'a IPLimits },
    Serve { version: IPVersion, protocol: IPProtocol, local: IPAddress, config: &'a IPServerConfig, limits: &'a IPLimits },
}

impl IPProviderRequest<'_> {
    pub fn version(&self) -> IPVersion {
        match self {
            Self::Open { version, .. } => *version,
            Self::Serve { version, .. } => *version,
        }
    }

    pub fn limits(&self) -> &IPLimits {
        match self {
            Self::Open { limits, .. } => limits,
            Self::Serve { limits, .. } => limits,
        }
    }
}

pub trait IPProvider: Provider {
    fn supports(&self, request: &IPProviderRequest<'_>) -> bool;

    fn open(&self, request: &IPProviderRequest<'_>) -> Result<ProviderHandle, ProviderError>;

    fn poll_ready(&self, handle: ProviderHandle, interest: ProviderInterest, cx: &mut Context<'_>) -> Poll<Result<(), ProviderError>>;

    fn send(&self, handle: ProviderHandle, destination: IPAddress, payload: &[u8]) -> Result<usize, ProviderError>;

    fn receive(&self, handle: ProviderHandle, payload: &mut [u8]) -> Result<(usize, IPAddress), ProviderError>;

    fn close(&self, handle: ProviderHandle) -> Result<(), ProviderError>;

    fn local(&self, handle: ProviderHandle) -> Result<IPAddress, ProviderError>;

    fn remote(&self, handle: ProviderHandle) -> Result<Option<IPAddress>, ProviderError>;

    fn protocol(&self, handle: ProviderHandle) -> Result<IPProtocol, ProviderError>;

    fn mtu(&self, handle: ProviderHandle) -> Result<usize, ProviderError>;
}

pub struct IPProviders;

impl IPProviders {
    pub fn global() -> &'static ProviderRegistry<dyn IPProvider> {
        static REGISTRY: ProviderRegistry<dyn IPProvider> = ProviderRegistry::new();
        &REGISTRY
    }

    pub fn open(request: &IPProviderRequest<'_>) -> Result<Option<ProviderOpening<dyn IPProvider>>, ProviderError> {
        Self::global().select(|provider| provider.supports(request)).open(|provider| provider.open(request))
    }
}

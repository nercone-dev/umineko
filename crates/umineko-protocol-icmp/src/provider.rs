use core::task::{Context, Poll};
use crate::types::{ICMPVersion, ICMPType, ICMPCode, ICMPLimits};
use crate::api::client::ICMPClientConfig;
use crate::api::server::ICMPServerConfig;

use umineko_protocol_ip::IPAddress;
use umineko_helpers::provider::{Provider, ProviderError, ProviderHandle, ProviderInterest, ProviderOpening, ProviderRegistry};

#[derive(Debug, Clone, Copy)]
pub enum ICMPProviderRequest<'a> {
    Open { version: ICMPVersion, local: Option<IPAddress>, remote: Option<IPAddress>, config: &'a ICMPClientConfig, limits: &'a ICMPLimits },
    Serve { version: ICMPVersion, local: IPAddress, config: &'a ICMPServerConfig, limits: &'a ICMPLimits },
}

impl ICMPProviderRequest<'_> {
    pub fn version(&self) -> ICMPVersion {
        match self {
            Self::Open { version, .. } => *version,
            Self::Serve { version, .. } => *version,
        }
    }

    pub fn limits(&self) -> &ICMPLimits {
        match self {
            Self::Open { limits, .. } => limits,
            Self::Serve { limits, .. } => limits,
        }
    }
}

pub trait ICMPProvider: Provider {
    fn supports(&self, request: &ICMPProviderRequest<'_>) -> bool;

    fn open(&self, request: &ICMPProviderRequest<'_>) -> Result<ProviderHandle, ProviderError>;

    fn poll_ready(&self, handle: ProviderHandle, interest: ProviderInterest, cx: &mut Context<'_>) -> Poll<Result<(), ProviderError>>;

    fn send(&self, handle: ProviderHandle, destination: IPAddress, kind: ICMPType, code: ICMPCode, payload: &[u8]) -> Result<usize, ProviderError>;

    fn receive(&self, handle: ProviderHandle, payload: &mut [u8]) -> Result<(ICMPType, ICMPCode, usize, IPAddress), ProviderError>;

    fn close(&self, handle: ProviderHandle) -> Result<(), ProviderError>;

    fn local(&self, handle: ProviderHandle) -> Result<IPAddress, ProviderError>;

    fn remote(&self, handle: ProviderHandle) -> Result<Option<IPAddress>, ProviderError>;
}

pub struct ICMPProviders;

impl ICMPProviders {
    pub fn global() -> &'static ProviderRegistry<dyn ICMPProvider> {
        static REGISTRY: ProviderRegistry<dyn ICMPProvider> = ProviderRegistry::new();
        &REGISTRY
    }

    pub fn open(request: &ICMPProviderRequest<'_>) -> Result<Option<ProviderOpening<dyn ICMPProvider>>, ProviderError> {
        Self::global().select(|provider| provider.supports(request)).open(|provider| provider.open(request))
    }
}

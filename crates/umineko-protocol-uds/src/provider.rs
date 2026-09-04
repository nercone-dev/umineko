use core::task::{Context, Poll};
use crate::types::{UDSPath, UDSType, UDSLimits};
use crate::helpers::ancillary::UDSAncillary;
use crate::helpers::credentials::UDSCredentials;
use crate::api::client::UDSClientConfig;
use crate::api::server::UDSServerConfig;

use umineko_helpers::provider::{Provider, ProviderError, ProviderHandle, ProviderInterest, ProviderOpening, ProviderRegistry};

#[derive(Debug, Clone, Copy)]
pub enum UDSProviderRequest<'a> {
    Connect { kind: UDSType, remote: &'a UDSPath, config: &'a UDSClientConfig, limits: &'a UDSLimits },
    Bind { kind: UDSType, local: &'a UDSPath, config: &'a UDSServerConfig, limits: &'a UDSLimits },
}

impl UDSProviderRequest<'_> {
    pub fn kind(&self) -> UDSType {
        match self {
            Self::Connect { kind, .. } => *kind,
            Self::Bind { kind, .. } => *kind,
        }
    }

    pub fn limits(&self) -> &UDSLimits {
        match self {
            Self::Connect { limits, .. } => limits,
            Self::Bind { limits, .. } => limits,
        }
    }
}

pub trait UDSProvider: Provider {
    fn supports(&self, request: &UDSProviderRequest<'_>) -> bool;

    fn open(&self, request: &UDSProviderRequest<'_>) -> Result<ProviderHandle, ProviderError>;

    fn poll_ready(&self, handle: ProviderHandle, interest: ProviderInterest, cx: &mut Context<'_>) -> Poll<Result<(), ProviderError>>;

    fn accept(&self, handle: ProviderHandle) -> Result<ProviderHandle, ProviderError>;

    fn send(&self, handle: ProviderHandle, data: &[u8]) -> Result<usize, ProviderError>;

    fn receive(&self, handle: ProviderHandle, data: &mut [u8]) -> Result<usize, ProviderError>;

    fn send_to(&self, handle: ProviderHandle, remote: &UDSPath, data: &[u8]) -> Result<usize, ProviderError>;

    fn receive_from(&self, handle: ProviderHandle, data: &mut [u8]) -> Result<(usize, UDSPath), ProviderError>;

    fn send_with(&self, handle: ProviderHandle, data: &[u8], ancillary: &UDSAncillary) -> Result<usize, ProviderError>;

    fn receive_with(&self, handle: ProviderHandle, data: &mut [u8]) -> Result<(usize, UDSAncillary), ProviderError>;

    fn credentials(&self, handle: ProviderHandle) -> Result<UDSCredentials, ProviderError>;

    fn shutdown(&self, handle: ProviderHandle) -> Result<(), ProviderError>;

    fn close(&self, handle: ProviderHandle) -> Result<(), ProviderError>;

    fn local(&self, handle: ProviderHandle) -> Result<UDSPath, ProviderError>;

    fn remote(&self, handle: ProviderHandle) -> Result<UDSPath, ProviderError>;
}

pub struct UDSProviders;

impl UDSProviders {
    pub fn global() -> &'static ProviderRegistry<dyn UDSProvider> {
        static REGISTRY: ProviderRegistry<dyn UDSProvider> = ProviderRegistry::new();
        &REGISTRY
    }

    pub fn open(request: &UDSProviderRequest<'_>) -> Result<Option<ProviderOpening<dyn UDSProvider>>, ProviderError> {
        Self::global().select(|provider| provider.supports(request)).open(|provider| provider.open(request))
    }
}

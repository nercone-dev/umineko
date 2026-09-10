use alloc::{string::String, vec::Vec};
use core::task::{Context, Poll};
use crate::types::{DNSName, DNSType, DNSClass, DNSRecord, DNSLimits};
use crate::helpers::resolver::DNSResolverMode;

use umineko_helpers::provider::{Provider, ProviderError, ProviderHandle, ProviderOpening, ProviderRegistry};

#[derive(Debug, Clone, Copy)]
pub struct DNSProviderRequest<'a> {
    pub name: &'a DNSName,
    pub kind: DNSType,
    pub class: DNSClass,
    pub mode: DNSResolverMode,
    pub servers: &'a [String],
    pub limits: &'a DNSLimits,
}

pub trait DNSProvider: Provider {
    fn supports(&self, request: &DNSProviderRequest<'_>) -> bool;

    fn open(&self, request: &DNSProviderRequest<'_>) -> Result<ProviderHandle, ProviderError>;

    fn poll_resolve(&self, handle: ProviderHandle, cx: &mut Context<'_>) -> Poll<Result<Vec<DNSRecord>, ProviderError>>;

    fn close(&self, handle: ProviderHandle) -> Result<(), ProviderError>;
}

pub struct DNSProviders;

impl DNSProviders {
    pub fn global() -> &'static ProviderRegistry<dyn DNSProvider> {
        static REGISTRY: ProviderRegistry<dyn DNSProvider> = ProviderRegistry::new();
        &REGISTRY
    }

    pub fn open(request: &DNSProviderRequest<'_>) -> Result<Option<ProviderOpening<dyn DNSProvider>>, ProviderError> {
        Self::global().select(|provider| provider.supports(request)).open(|provider| provider.open(request))
    }
}

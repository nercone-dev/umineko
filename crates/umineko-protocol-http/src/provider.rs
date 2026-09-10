use core::task::{Context, Poll};
use crate::types::{HTTPMessage, HTTPLimits};
use crate::api::client::HTTPClientConfig;

use umineko_url::URL;
use umineko_helpers::provider::{Provider, ProviderError, ProviderHandle, ProviderOpening, ProviderRegistry};

#[derive(Debug, Clone, Copy)]
pub struct HTTPProviderRequest<'a> {
    pub url: &'a URL,
    pub message: &'a HTTPMessage,
    pub config: &'a HTTPClientConfig,
    pub limits: &'a HTTPLimits,
}

pub trait HTTPProvider: Provider {
    fn supports(&self, request: &HTTPProviderRequest<'_>) -> bool;

    fn open(&self, request: &HTTPProviderRequest<'_>) -> Result<ProviderHandle, ProviderError>;

    fn poll_response(&self, handle: ProviderHandle, cx: &mut Context<'_>) -> Poll<Result<HTTPMessage, ProviderError>>;

    fn poll_body(&self, handle: ProviderHandle, data: &mut [u8], cx: &mut Context<'_>) -> Poll<Result<usize, ProviderError>>;

    fn cancel(&self, handle: ProviderHandle) -> Result<(), ProviderError>;

    fn close(&self, handle: ProviderHandle) -> Result<(), ProviderError>;
}

pub struct HTTPProviders;

impl HTTPProviders {
    pub fn global() -> &'static ProviderRegistry<dyn HTTPProvider> {
        static REGISTRY: ProviderRegistry<dyn HTTPProvider> = ProviderRegistry::new();
        &REGISTRY
    }

    pub fn open(request: &HTTPProviderRequest<'_>) -> Result<Option<ProviderOpening<dyn HTTPProvider>>, ProviderError> {
        Self::global().select(|provider| provider.supports(request)).open(|provider| provider.open(request))
    }
}

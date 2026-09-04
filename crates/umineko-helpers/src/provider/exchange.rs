use alloc::vec::Vec;
use crate::provider::base::{Provider, ProviderError};
use crate::provider::registry::ProviderRegistry;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExchangeProviderRequest<'a> {
    pub algorithm: &'static str,
    pub seed: Option<&'a [u8]>,
}

impl<'a> ExchangeProviderRequest<'a> {
    pub fn new(algorithm: &'static str) -> Self {
        Self { algorithm, seed: None }
    }

    pub fn with_seed(self, seed: &'a [u8]) -> Self {
        Self { seed: Some(seed), ..self }
    }
}

pub trait ExchangeProvider: Provider {
    fn supports(&self, request: &ExchangeProviderRequest<'_>) -> bool;

    fn generate(&self, request: &ExchangeProviderRequest<'_>) -> Result<(Vec<u8>, Vec<u8>), ProviderError>;

    fn public_key(&self, request: &ExchangeProviderRequest<'_>, private: &[u8]) -> Result<Vec<u8>, ProviderError>;

    fn exchange(&self, request: &ExchangeProviderRequest<'_>, private: &[u8], peer: &[u8]) -> Result<Vec<u8>, ProviderError> {
        let _ = (request, private, peer);
        Err(ProviderError::Unsupported)
    }

    fn encapsulate(&self, request: &ExchangeProviderRequest<'_>, public: &[u8]) -> Result<(Vec<u8>, Vec<u8>), ProviderError> {
        let _ = (request, public);
        Err(ProviderError::Unsupported)
    }

    fn decapsulate(&self, request: &ExchangeProviderRequest<'_>, private: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, ProviderError> {
        let _ = (request, private, ciphertext);
        Err(ProviderError::Unsupported)
    }
}

pub struct ExchangeProviders;

impl ExchangeProviders {
    pub fn global() -> &'static ProviderRegistry<dyn ExchangeProvider> {
        static REGISTRY: ProviderRegistry<dyn ExchangeProvider> = ProviderRegistry::new();
        &REGISTRY
    }

    #[allow(clippy::type_complexity)]
    pub fn generate(request: &ExchangeProviderRequest<'_>) -> Result<Option<(Vec<u8>, Vec<u8>)>, ProviderError> {
        Self::global().select(|provider| provider.supports(request)).resolve(|provider| provider.generate(request))
    }

    pub fn public_key(request: &ExchangeProviderRequest<'_>, private: &[u8]) -> Result<Option<Vec<u8>>, ProviderError> {
        Self::global().select(|provider| provider.supports(request)).resolve(|provider| provider.public_key(request, private))
    }

    pub fn exchange(request: &ExchangeProviderRequest<'_>, private: &[u8], peer: &[u8]) -> Result<Option<Vec<u8>>, ProviderError> {
        Self::global().select(|provider| provider.supports(request)).resolve(|provider| provider.exchange(request, private, peer))
    }

    #[allow(clippy::type_complexity)]
    pub fn encapsulate(request: &ExchangeProviderRequest<'_>, public: &[u8]) -> Result<Option<(Vec<u8>, Vec<u8>)>, ProviderError> {
        Self::global().select(|provider| provider.supports(request)).resolve(|provider| provider.encapsulate(request, public))
    }

    pub fn decapsulate(request: &ExchangeProviderRequest<'_>, private: &[u8], ciphertext: &[u8]) -> Result<Option<Vec<u8>>, ProviderError> {
        Self::global().select(|provider| provider.supports(request)).resolve(|provider| provider.decapsulate(request, private, ciphertext))
    }
}

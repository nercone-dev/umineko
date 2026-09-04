use alloc::vec::Vec;
use crate::provider::base::{Provider, ProviderError};
use crate::provider::registry::ProviderRegistry;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignatureProviderRequest<'a> {
    pub algorithm: &'static str,
    pub context: &'a [u8],
    pub seed: Option<&'a [u8]>,
}

impl<'a> SignatureProviderRequest<'a> {
    pub fn new(algorithm: &'static str) -> Self {
        Self { algorithm, context: &[], seed: None }
    }

    pub fn with_context(self, context: &'a [u8]) -> Self {
        Self { context, ..self }
    }

    pub fn with_seed(self, seed: &'a [u8]) -> Self {
        Self { seed: Some(seed), ..self }
    }
}

pub trait SignatureProvider: Provider {
    fn supports(&self, request: &SignatureProviderRequest<'_>) -> bool;

    fn generate(&self, request: &SignatureProviderRequest<'_>) -> Result<(Vec<u8>, Vec<u8>), ProviderError>;

    fn public_key(&self, request: &SignatureProviderRequest<'_>, private: &[u8]) -> Result<Vec<u8>, ProviderError>;

    fn sign(&self, request: &SignatureProviderRequest<'_>, private: &[u8], message: &[u8]) -> Result<Vec<u8>, ProviderError>;

    fn verify(&self, request: &SignatureProviderRequest<'_>, public: &[u8], message: &[u8], signature: &[u8]) -> Result<(), ProviderError>;
}

pub struct SignatureProviders;

impl SignatureProviders {
    pub fn global() -> &'static ProviderRegistry<dyn SignatureProvider> {
        static REGISTRY: ProviderRegistry<dyn SignatureProvider> = ProviderRegistry::new();
        &REGISTRY
    }

    #[allow(clippy::type_complexity)]
    pub fn generate(request: &SignatureProviderRequest<'_>) -> Result<Option<(Vec<u8>, Vec<u8>)>, ProviderError> {
        Self::global().select(|provider| provider.supports(request)).resolve(|provider| provider.generate(request))
    }

    pub fn public_key(request: &SignatureProviderRequest<'_>, private: &[u8]) -> Result<Option<Vec<u8>>, ProviderError> {
        Self::global().select(|provider| provider.supports(request)).resolve(|provider| provider.public_key(request, private))
    }

    pub fn sign(request: &SignatureProviderRequest<'_>, private: &[u8], message: &[u8]) -> Result<Option<Vec<u8>>, ProviderError> {
        Self::global().select(|provider| provider.supports(request)).resolve(|provider| provider.sign(request, private, message))
    }

    pub fn verify(request: &SignatureProviderRequest<'_>, public: &[u8], message: &[u8], signature: &[u8]) -> Result<Option<()>, ProviderError> {
        Self::global().select(|provider| provider.supports(request)).resolve(|provider| provider.verify(request, public, message, signature))
    }
}

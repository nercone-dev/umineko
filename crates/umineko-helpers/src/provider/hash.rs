use crate::provider::base::{Provider, ProviderError, ProviderHandle};
use crate::provider::backend::{ProviderBackend, ProviderOpening};
use crate::provider::registry::ProviderRegistry;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HashProviderRequest<'a> {
    pub algorithm: &'static str,
    pub key: Option<&'a [u8]>,
    pub seed: Option<u64>,
    pub digest_size: Option<usize>,
    pub customization: Option<&'a [u8]>,
    pub streaming: bool,
}

impl<'a> HashProviderRequest<'a> {
    pub fn new(algorithm: &'static str) -> Self {
        Self { algorithm, key: None, seed: None, digest_size: None, customization: None, streaming: true }
    }

    pub fn with_key(self, key: &'a [u8]) -> Self {
        Self { key: Some(key), ..self }
    }

    pub fn with_seed(self, seed: u64) -> Self {
        Self { seed: Some(seed), ..self }
    }

    pub fn with_digest_size(self, digest_size: usize) -> Self {
        Self { digest_size: Some(digest_size), ..self }
    }

    pub fn with_customization(self, customization: &'a [u8]) -> Self {
        Self { customization: Some(customization), ..self }
    }

    pub fn one_shot(self) -> Self {
        Self { streaming: false, ..self }
    }
}

pub trait HashProvider: Provider {
    fn supports(&self, request: &HashProviderRequest<'_>) -> bool;

    fn open(&self, request: &HashProviderRequest<'_>) -> Result<ProviderHandle, ProviderError>;

    fn update(&self, handle: ProviderHandle, data: &[u8]);

    fn finalize(&self, handle: ProviderHandle, digest: &mut [u8]) -> usize;

    fn reset(&self, handle: ProviderHandle);

    fn duplicate(&self, handle: ProviderHandle) -> ProviderHandle;

    fn digest(&self, request: &HashProviderRequest<'_>, data: &[u8], digest: &mut [u8]) -> Result<usize, ProviderError> {
        let handle = self.open(request)?;
        self.update(handle, data);
        let length = self.finalize(handle, digest);
        self.release(handle);
        Ok(length)
    }
}

pub struct HashProviders;

impl HashProviders {
    pub fn global() -> &'static ProviderRegistry<dyn HashProvider> {
        static REGISTRY: ProviderRegistry<dyn HashProvider> = ProviderRegistry::new();
        &REGISTRY
    }

    pub fn open(request: &HashProviderRequest<'_>) -> Result<Option<ProviderOpening<dyn HashProvider>>, ProviderError> {
        Self::global().select(|provider| provider.supports(request)).open(|provider| provider.open(request))
    }

    /// Panics when the policy excludes the builtin implementation and every provider failed.
    pub fn backend(request: &HashProviderRequest<'_>) -> ProviderBackend<dyn HashProvider> {
        Self::global().select(|provider| provider.supports(request)).backend(|provider| provider.open(request))
    }

    /// Returns `None` when the builtin implementation is selected. Panics when the policy excludes it and every provider failed.
    pub fn digest(request: &HashProviderRequest<'_>, data: &[u8], digest: &mut [u8]) -> Option<usize> {
        let request = request.one_shot();
        Self::global().select(|provider| provider.supports(&request)).require(|provider| provider.digest(&request, data, digest))
    }

    pub fn try_digest(request: &HashProviderRequest<'_>, data: &[u8], digest: &mut [u8]) -> Result<Option<usize>, ProviderError> {
        let request = request.one_shot();
        Self::global().select(|provider| provider.supports(&request)).resolve(|provider| provider.digest(&request, data, digest))
    }
}

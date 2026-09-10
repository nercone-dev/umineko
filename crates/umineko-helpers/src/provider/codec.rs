use alloc::vec::Vec;
use crate::provider::base::{Provider, ProviderError, ProviderHandle};
use crate::provider::backend::{ProviderBackend, ProviderOpening};
use crate::provider::registry::ProviderRegistry;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CodecDirection {
    Encode,
    Decode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodecProviderRequest<'a> {
    pub algorithm: &'static str,
    pub direction: CodecDirection,
    pub level: Option<i32>,
    pub window: Option<u8>,
    pub limit: Option<usize>,
    pub parameters: Option<&'a [u8]>,
}

impl<'a> CodecProviderRequest<'a> {
    pub fn new(algorithm: &'static str, direction: CodecDirection) -> Self {
        Self { algorithm, direction, level: None, window: None, limit: None, parameters: None }
    }

    pub fn with_level(self, level: i32) -> Self {
        Self { level: Some(level), ..self }
    }

    pub fn with_window(self, window: u8) -> Self {
        Self { window: Some(window), ..self }
    }

    pub fn with_limit(self, limit: Option<usize>) -> Self {
        Self { limit, ..self }
    }

    pub fn with_parameters(self, parameters: &'a [u8]) -> Self {
        Self { parameters: Some(parameters), ..self }
    }
}

pub trait CodecProvider: Provider {
    fn supports(&self, request: &CodecProviderRequest<'_>) -> bool;

    fn open(&self, request: &CodecProviderRequest<'_>) -> Result<ProviderHandle, ProviderError>;

    fn update(&self, handle: ProviderHandle, data: &[u8]) -> Result<Vec<u8>, ProviderError>;

    fn finalize(&self, handle: ProviderHandle) -> Result<Vec<u8>, ProviderError>;

    fn reset(&self, handle: ProviderHandle);

    fn transform(&self, request: &CodecProviderRequest<'_>, data: &[u8]) -> Result<Vec<u8>, ProviderError> {
        let handle = self.open(request)?;
        let result = self.update(handle, data).and_then(|mut output| {
            self.finalize(handle).map(|tail| {
                output.extend_from_slice(&tail);
                output
            })
        });
        self.release(handle);
        result
    }
}

pub struct CodecProviders;

impl CodecProviders {
    pub fn global() -> &'static ProviderRegistry<dyn CodecProvider> {
        static REGISTRY: ProviderRegistry<dyn CodecProvider> = ProviderRegistry::new();
        &REGISTRY
    }

    pub fn open(request: &CodecProviderRequest<'_>) -> Result<Option<ProviderOpening<dyn CodecProvider>>, ProviderError> {
        Self::global().select(|provider| provider.supports(request)).open(|provider| provider.open(request))
    }

    /// Panics when the policy excludes the builtin implementation and every provider failed.
    pub fn backend(request: &CodecProviderRequest<'_>) -> ProviderBackend<dyn CodecProvider> {
        Self::global().select(|provider| provider.supports(request)).backend(|provider| provider.open(request))
    }

    pub fn transform(request: &CodecProviderRequest<'_>, data: &[u8]) -> Result<Option<Vec<u8>>, ProviderError> {
        Self::global().select(|provider| provider.supports(request)).resolve(|provider| provider.transform(request, data))
    }
}

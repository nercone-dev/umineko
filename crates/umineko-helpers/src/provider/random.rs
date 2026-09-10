use crate::provider::base::{Provider, ProviderError, ProviderHandle};
use crate::provider::backend::{ProviderBackend, ProviderOpening};
use crate::provider::registry::ProviderRegistry;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RandomProviderRequest<'a> {
    pub algorithm: &'static str,
    pub entropy: &'a [u8],
    pub nonce: &'a [u8],
    pub personalization: &'a [u8],
    pub security_strength: Option<usize>,
    pub prediction_resistance: bool,
}

impl<'a> RandomProviderRequest<'a> {
    pub fn new(algorithm: &'static str) -> Self {
        Self { algorithm, entropy: &[], nonce: &[], personalization: &[], security_strength: None, prediction_resistance: false }
    }

    pub fn with_entropy(self, entropy: &'a [u8]) -> Self {
        Self { entropy, ..self }
    }

    pub fn with_nonce(self, nonce: &'a [u8]) -> Self {
        Self { nonce, ..self }
    }

    pub fn with_personalization(self, personalization: &'a [u8]) -> Self {
        Self { personalization, ..self }
    }

    pub fn with_security_strength(self, security_strength: usize) -> Self {
        Self { security_strength: Some(security_strength), ..self }
    }

    pub fn with_prediction_resistance(self, prediction_resistance: bool) -> Self {
        Self { prediction_resistance, ..self }
    }
}

pub trait RandomProvider: Provider {
    fn supports(&self, request: &RandomProviderRequest<'_>) -> bool;

    fn open(&self, request: &RandomProviderRequest<'_>) -> Result<ProviderHandle, ProviderError>;

    fn reseed(&self, handle: ProviderHandle, entropy: &[u8], additional: &[u8]) -> Result<(), ProviderError>;

    fn generate(&self, handle: ProviderHandle, output: &mut [u8], additional: &[u8]) -> Result<(), ProviderError>;

    fn fill(&self, request: &RandomProviderRequest<'_>, output: &mut [u8]) -> Result<(), ProviderError> {
        let handle = self.open(request)?;
        let result = self.generate(handle, output, &[]);
        self.release(handle);
        result
    }
}

pub struct RandomProviders;

impl RandomProviders {
    pub fn global() -> &'static ProviderRegistry<dyn RandomProvider> {
        static REGISTRY: ProviderRegistry<dyn RandomProvider> = ProviderRegistry::new();
        &REGISTRY
    }

    pub fn open(request: &RandomProviderRequest<'_>) -> Result<Option<ProviderOpening<dyn RandomProvider>>, ProviderError> {
        Self::global().select(|provider| provider.supports(request)).open(|provider| provider.open(request))
    }

    /// Panics when the policy excludes the builtin implementation and every provider failed.
    pub fn backend(request: &RandomProviderRequest<'_>) -> ProviderBackend<dyn RandomProvider> {
        Self::global().select(|provider| provider.supports(request)).backend(|provider| provider.open(request))
    }

    pub fn fill(request: &RandomProviderRequest<'_>, output: &mut [u8]) -> Result<Option<()>, ProviderError> {
        Self::global().select(|provider| provider.supports(request)).resolve(|provider| provider.fill(request, output))
    }
}

use crate::provider::base::{Provider, ProviderError};
use crate::provider::registry::ProviderRegistry;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KDFProviderRequest {
    pub algorithm: &'static str,
    pub prf: Option<&'static str>,
    pub digest: Option<&'static str>,
    pub iterations: u32,
    pub cost: u32,
    pub block: u32,
    pub parallelism: u32,
    pub memory: u32,
    pub version: u32,
}

impl KDFProviderRequest {
    pub fn new(algorithm: &'static str) -> Self {
        Self { algorithm, prf: None, digest: None, iterations: 0, cost: 0, block: 0, parallelism: 0, memory: 0, version: 0 }
    }

    pub fn with_prf(self, prf: &'static str) -> Self {
        Self { prf: Some(prf), ..self }
    }

    /// Names the hash the pseudorandom function is built over, where it has one.
    pub fn with_digest(self, digest: &'static str) -> Self {
        Self { digest: Some(digest), ..self }
    }

    pub fn with_iterations(self, iterations: u32) -> Self {
        Self { iterations, ..self }
    }

    pub fn with_cost(self, cost: u32, block: u32, parallelism: u32) -> Self {
        Self { cost, block, parallelism, ..self }
    }

    pub fn with_memory(self, memory: u32, iterations: u32, parallelism: u32, version: u32) -> Self {
        Self { memory, iterations, parallelism, version, ..self }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KDFProviderInputs<'a> {
    pub key: &'a [u8],
    pub salt: &'a [u8],
    pub info: &'a [u8],
    pub secret: &'a [u8],
    pub associated: &'a [u8],
}

impl<'a> KDFProviderInputs<'a> {
    pub fn new(key: &'a [u8], salt: &'a [u8]) -> Self {
        Self { key, salt, info: &[], secret: &[], associated: &[] }
    }

    pub fn with_info(self, info: &'a [u8]) -> Self {
        Self { info, ..self }
    }

    pub fn with_secret(self, secret: &'a [u8]) -> Self {
        Self { secret, ..self }
    }

    pub fn with_associated(self, associated: &'a [u8]) -> Self {
        Self { associated, ..self }
    }
}

pub trait KDFProvider: Provider {
    fn supports(&self, request: &KDFProviderRequest) -> bool;

    fn derive(&self, request: &KDFProviderRequest, inputs: &KDFProviderInputs<'_>, output: &mut [u8]) -> Result<(), ProviderError>;
}

pub struct KDFProviders;

impl KDFProviders {
    pub fn global() -> &'static ProviderRegistry<dyn KDFProvider> {
        static REGISTRY: ProviderRegistry<dyn KDFProvider> = ProviderRegistry::new();
        &REGISTRY
    }

    pub fn derive(request: &KDFProviderRequest, inputs: &KDFProviderInputs<'_>, output: &mut [u8]) -> Result<Option<()>, ProviderError> {
        Self::global().select(|provider| provider.supports(request)).resolve(|provider| provider.derive(request, inputs, output))
    }
}

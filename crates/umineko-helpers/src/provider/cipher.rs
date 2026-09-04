use alloc::vec::Vec;
use crate::provider::base::{Provider, ProviderError};
use crate::provider::registry::ProviderRegistry;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CipherProviderRequest<'a> {
    pub algorithm: &'static str,
    pub key: &'a [u8],
    pub nonce: &'a [u8],
    pub associated: &'a [u8],
    pub counter: u32,
    pub padding: bool,
}

impl<'a> CipherProviderRequest<'a> {
    pub fn new(algorithm: &'static str, key: &'a [u8]) -> Self {
        Self { algorithm, key, nonce: &[], associated: &[], counter: 0, padding: false }
    }

    pub fn with_nonce(self, nonce: &'a [u8]) -> Self {
        Self { nonce, ..self }
    }

    pub fn with_associated(self, associated: &'a [u8]) -> Self {
        Self { associated, ..self }
    }

    pub fn with_counter(self, counter: u32) -> Self {
        Self { counter, ..self }
    }

    pub fn with_padding(self, padding: bool) -> Self {
        Self { padding, ..self }
    }
}

pub trait CipherProvider: Provider {
    fn supports(&self, request: &CipherProviderRequest<'_>) -> bool;

    fn encrypt(&self, request: &CipherProviderRequest<'_>, plaintext: &[u8]) -> Result<Vec<u8>, ProviderError>;

    fn decrypt(&self, request: &CipherProviderRequest<'_>, ciphertext: &[u8]) -> Result<Vec<u8>, ProviderError>;
}

pub struct CipherProviders;

impl CipherProviders {
    pub fn global() -> &'static ProviderRegistry<dyn CipherProvider> {
        static REGISTRY: ProviderRegistry<dyn CipherProvider> = ProviderRegistry::new();
        &REGISTRY
    }

    pub fn encrypt(request: &CipherProviderRequest<'_>, plaintext: &[u8]) -> Result<Option<Vec<u8>>, ProviderError> {
        Self::global().select(|provider| provider.supports(request)).resolve(|provider| provider.encrypt(request, plaintext))
    }

    pub fn decrypt(request: &CipherProviderRequest<'_>, ciphertext: &[u8]) -> Result<Option<Vec<u8>>, ProviderError> {
        Self::global().select(|provider| provider.supports(request)).resolve(|provider| provider.decrypt(request, ciphertext))
    }
}

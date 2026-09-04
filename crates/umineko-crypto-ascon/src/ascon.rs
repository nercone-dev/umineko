use alloc::vec::Vec;
use crate::errors::AsconError;

use umineko_helpers::provider::{CipherProviderRequest, CipherProviders, HashProvider, HashProviderRequest, HashProviders, ProviderBackend, ProviderOpening};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsconAEAD128 {
    key: [u8; 16],
    state: [u64; 5],
}

impl AsconAEAD128 {
    pub const NAME: &'static str = "Ascon-AEAD128";
    pub const KEY_SIZE: usize = 16;
    pub const NONCE_SIZE: usize = 16;
    pub const TAG_SIZE: usize = 16;
    pub const RATE: usize = 16;

    pub fn new(key: &[u8; 16]) -> Self {
        Self { key: *key, state: [0; 5] }
    }

    pub fn request<'a>(&'a self, nonce: &'a [u8; 16], associated: &'a [u8]) -> CipherProviderRequest<'a> {
        CipherProviderRequest::new(Self::NAME, &self.key).with_nonce(nonce).with_associated(associated)
    }

    pub fn encrypt(&self, nonce: &[u8; 16], associated: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, AsconError> {
        match CipherProviders::encrypt(&self.request(nonce, associated), plaintext)? {
            Some(ciphertext) => Ok(ciphertext),
            None => todo!(),
        }
    }

    pub fn decrypt(&self, nonce: &[u8; 16], associated: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, AsconError> {
        match CipherProviders::decrypt(&self.request(nonce, associated), ciphertext)? {
            Some(plaintext) => Ok(plaintext),
            None => todo!(),
        }
    }
}

#[derive(Debug)]
pub struct AsconHash256 {
    state: [u64; 5],
    buffer: [u8; 8],
    length: usize,
    backend: ProviderBackend<dyn HashProvider>,
}

impl AsconHash256 {
    pub const NAME: &'static str = "Ascon-Hash256";
    pub const DIGEST_SIZE: usize = 32;
    pub const RATE: usize = 8;

    pub fn new() -> Self {
        match HashProviders::backend(&Self::request()) {
            ProviderBackend::Builtin => todo!(),
            backend => Self { state: [0; 5], buffer: [0; 8], length: 0, backend },
        }
    }

    pub fn request() -> HashProviderRequest<'static> {
        HashProviderRequest::new(Self::NAME)
    }

    pub fn update(&mut self, data: &[u8]) {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => provider.update(*handle, data),
        }
    }

    pub fn finalize(self) -> [u8; 32] {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => {
                let mut digest = [0; 32];
                provider.finalize(*handle, &mut digest);
                digest
            }
        }
    }

    pub fn reset(&mut self) {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => provider.reset(*handle),
        }
    }

    pub fn digest(data: &[u8]) -> [u8; 32] {
        let mut digest = [0; 32];
        match HashProviders::digest(&Self::request(), data, &mut digest) {
            Some(_) => digest,
            None => todo!(),
        }
    }
}

impl Clone for AsconHash256 {
    fn clone(&self) -> Self {
        Self { state: self.state, buffer: self.buffer, length: self.length, backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)) }
    }
}

impl Default for AsconHash256 {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct AsconXOF128 {
    state: [u64; 5],
    buffer: [u8; 8],
    length: usize,
    backend: ProviderBackend<dyn HashProvider>,
}

impl AsconXOF128 {
    pub const NAME: &'static str = "Ascon-XOF128";
    pub const RATE: usize = 8;

    pub fn new() -> Self {
        match HashProviders::backend(&Self::request()) {
            ProviderBackend::Builtin => todo!(),
            backend => Self { state: [0; 5], buffer: [0; 8], length: 0, backend },
        }
    }

    pub fn request() -> HashProviderRequest<'static> {
        HashProviderRequest::new(Self::NAME)
    }

    pub fn update(&mut self, data: &[u8]) {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => provider.update(*handle, data),
        }
    }

    pub fn finalize(self, digest: &mut [u8]) {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => {
                provider.finalize(*handle, digest);
            }
        }
    }

    pub fn reset(&mut self) {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => provider.reset(*handle),
        }
    }

    pub fn digest(data: &[u8], digest: &mut [u8]) {
        match HashProviders::digest(&Self::request(), data, digest) {
            Some(_) => {}
            None => todo!(),
        }
    }
}

impl Clone for AsconXOF128 {
    fn clone(&self) -> Self {
        Self { state: self.state, buffer: self.buffer, length: self.length, backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)) }
    }
}

impl Default for AsconXOF128 {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct AsconCXOF128 {
    state: [u64; 5],
    buffer: [u8; 8],
    length: usize,
    backend: ProviderBackend<dyn HashProvider>,
}

impl AsconCXOF128 {
    pub const NAME: &'static str = "Ascon-CXOF128";
    pub const RATE: usize = 8;
    pub const MAX_CUSTOMIZATION_SIZE: usize = 256;

    pub fn new(customization: &[u8]) -> Result<Self, AsconError> {
        if customization.len() > Self::MAX_CUSTOMIZATION_SIZE {
            return Err(AsconError::Length);
        }
        match HashProviders::open(&Self::request(customization))? {
            Some(ProviderOpening { provider, handle }) => Ok(Self { state: [0; 5], buffer: [0; 8], length: 0, backend: ProviderBackend::Handle { provider, handle } }),
            None => todo!(),
        }
    }

    pub fn request(customization: &[u8]) -> HashProviderRequest<'_> {
        HashProviderRequest::new(Self::NAME).with_customization(customization)
    }

    pub fn update(&mut self, data: &[u8]) {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => provider.update(*handle, data),
        }
    }

    pub fn finalize(self, digest: &mut [u8]) {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => {
                provider.finalize(*handle, digest);
            }
        }
    }

    pub fn reset(&mut self) {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => provider.reset(*handle),
        }
    }

    pub fn digest(customization: &[u8], data: &[u8], digest: &mut [u8]) -> Result<(), AsconError> {
        if customization.len() > Self::MAX_CUSTOMIZATION_SIZE {
            return Err(AsconError::Length);
        }
        match HashProviders::try_digest(&Self::request(customization), data, digest)? {
            Some(_) => Ok(()),
            None => todo!(),
        }
    }
}

impl Clone for AsconCXOF128 {
    fn clone(&self) -> Self {
        Self { state: self.state, buffer: self.buffer, length: self.length, backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)) }
    }
}

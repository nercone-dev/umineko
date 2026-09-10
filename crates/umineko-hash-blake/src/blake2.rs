use core::fmt;

use umineko_helpers::provider::{HashProvider, HashProviderRequest, HashProviders, ProviderBackend};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BLAKE2 {
    S,
    B,
}

impl BLAKE2 {
    pub fn digest_size(&self) -> usize {
        match self {
            Self::S => 32,
            Self::B => 64,
        }
    }

    pub fn block_size(&self) -> usize {
        match self {
            Self::S => 64,
            Self::B => 128,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::S => "BLAKE2s",
            Self::B => "BLAKE2b",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "BLAKE2s" => Some(Self::S),
            "BLAKE2b" => Some(Self::B),
            _ => None,
        }
    }
}

impl fmt::Display for BLAKE2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug)]
pub struct BLAKE2S {
    state: [u32; 8],
    buffer: [u8; 64],
    length: u64,
    digest_size: usize,
    backend: ProviderBackend<dyn HashProvider>,
}

impl BLAKE2S {
    pub const NAME: &'static str = "BLAKE2s";
    pub const BLOCK_SIZE: usize = 64;

    pub fn new(digest_size: usize) -> Self {
        match HashProviders::backend(&Self::request(digest_size)) {
            ProviderBackend::Builtin => todo!(),
            backend => Self { state: [0; 8], buffer: [0; 64], length: 0, digest_size, backend },
        }
    }

    pub fn with_key(digest_size: usize, key: &[u8]) -> Self {
        match HashProviders::backend(&Self::request(digest_size).with_key(key)) {
            ProviderBackend::Builtin => todo!(),
            backend => Self { state: [0; 8], buffer: [0; 64], length: 0, digest_size, backend },
        }
    }

    pub fn request<'a>(digest_size: usize) -> HashProviderRequest<'a> {
        HashProviderRequest::new(Self::NAME).with_digest_size(digest_size)
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
        match HashProviders::digest(&Self::request(digest.len()), data, digest) {
            Some(_) => {}
            None => todo!(),
        }
    }
}

impl Clone for BLAKE2S {
    fn clone(&self) -> Self {
        Self { state: self.state, buffer: self.buffer, length: self.length, digest_size: self.digest_size, backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)) }
    }
}

#[derive(Debug)]
pub struct BLAKE2B {
    state: [u64; 8],
    buffer: [u8; 128],
    length: u128,
    digest_size: usize,
    backend: ProviderBackend<dyn HashProvider>,
}

impl BLAKE2B {
    pub const NAME: &'static str = "BLAKE2b";
    pub const BLOCK_SIZE: usize = 128;

    pub fn new(digest_size: usize) -> Self {
        match HashProviders::backend(&Self::request(digest_size)) {
            ProviderBackend::Builtin => todo!(),
            backend => Self { state: [0; 8], buffer: [0; 128], length: 0, digest_size, backend },
        }
    }

    pub fn with_key(digest_size: usize, key: &[u8]) -> Self {
        match HashProviders::backend(&Self::request(digest_size).with_key(key)) {
            ProviderBackend::Builtin => todo!(),
            backend => Self { state: [0; 8], buffer: [0; 128], length: 0, digest_size, backend },
        }
    }

    pub fn request<'a>(digest_size: usize) -> HashProviderRequest<'a> {
        HashProviderRequest::new(Self::NAME).with_digest_size(digest_size)
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
        match HashProviders::digest(&Self::request(digest.len()), data, digest) {
            Some(_) => {}
            None => todo!(),
        }
    }
}

impl Clone for BLAKE2B {
    fn clone(&self) -> Self {
        Self { state: self.state, buffer: self.buffer, length: self.length, digest_size: self.digest_size, backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)) }
    }
}

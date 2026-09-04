use core::fmt;

use umineko_helpers::provider::{HashProvider, HashProviderRequest, HashProviders, ProviderBackend};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum XXH3 {
    V64,
    V128,
}

impl XXH3 {
    pub fn digest_size(&self) -> usize {
        match self {
            Self::V64 => 8,
            Self::V128 => 16,
        }
    }

    pub fn block_size(&self) -> usize {
        match self {
            Self::V64 => 64,
            Self::V128 => 64,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::V64 => "XXH3-64",
            Self::V128 => "XXH3-128",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "XXH3-64" => Some(Self::V64),
            "XXH3-128" => Some(Self::V128),
            _ => None,
        }
    }
}

impl fmt::Display for XXH3 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug)]
pub struct XXH3_64 {
    accumulator: [u64; 8],
    secret: [u8; 192],
    buffer: [u8; 256],
    length: u64,
    seed: u64,
    backend: ProviderBackend<dyn HashProvider>,
}

impl XXH3_64 {
    pub const NAME: &'static str = "XXH3-64";
    pub const DIGEST_SIZE: usize = 8;
    pub const BLOCK_SIZE: usize = 64;

    pub fn new() -> Self {
        match HashProviders::backend(&Self::request()) {
            ProviderBackend::Builtin => todo!(),
            backend => Self { accumulator: [0; 8], secret: [0; 192], buffer: [0; 256], length: 0, seed: 0, backend },
        }
    }

    pub fn request() -> HashProviderRequest<'static> {
        HashProviderRequest::new(Self::NAME)
    }

    pub fn with_seed(seed: u64) -> Self {
        match HashProviders::backend(&Self::request().with_seed(seed)) {
            ProviderBackend::Builtin => todo!(),
            backend => Self { accumulator: [0; 8], secret: [0; 192], buffer: [0; 256], length: 0, seed, backend },
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => provider.update(*handle, data),
        }
    }

    pub fn finalize(self) -> [u8; 8] {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => {
                let mut digest = [0; 8];
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

    pub fn digest(data: &[u8]) -> [u8; 8] {
        let mut digest = [0; 8];
        match HashProviders::digest(&Self::request(), data, &mut digest) {
            Some(_) => digest,
            None => todo!(),
        }
    }
}

impl Clone for XXH3_64 {
    fn clone(&self) -> Self {
        Self { accumulator: self.accumulator, secret: self.secret, buffer: self.buffer, length: self.length, seed: self.seed, backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)) }
    }
}

impl Default for XXH3_64 {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct XXH3_128 {
    accumulator: [u64; 8],
    secret: [u8; 192],
    buffer: [u8; 256],
    length: u64,
    seed: u64,
    backend: ProviderBackend<dyn HashProvider>,
}

impl XXH3_128 {
    pub const NAME: &'static str = "XXH3-128";
    pub const DIGEST_SIZE: usize = 16;
    pub const BLOCK_SIZE: usize = 64;

    pub fn new() -> Self {
        match HashProviders::backend(&Self::request()) {
            ProviderBackend::Builtin => todo!(),
            backend => Self { accumulator: [0; 8], secret: [0; 192], buffer: [0; 256], length: 0, seed: 0, backend },
        }
    }

    pub fn request() -> HashProviderRequest<'static> {
        HashProviderRequest::new(Self::NAME)
    }

    pub fn with_seed(seed: u64) -> Self {
        match HashProviders::backend(&Self::request().with_seed(seed)) {
            ProviderBackend::Builtin => todo!(),
            backend => Self { accumulator: [0; 8], secret: [0; 192], buffer: [0; 256], length: 0, seed, backend },
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => provider.update(*handle, data),
        }
    }

    pub fn finalize(self) -> [u8; 16] {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => {
                let mut digest = [0; 16];
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

    pub fn digest(data: &[u8]) -> [u8; 16] {
        let mut digest = [0; 16];
        match HashProviders::digest(&Self::request(), data, &mut digest) {
            Some(_) => digest,
            None => todo!(),
        }
    }
}

impl Clone for XXH3_128 {
    fn clone(&self) -> Self {
        Self { accumulator: self.accumulator, secret: self.secret, buffer: self.buffer, length: self.length, seed: self.seed, backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)) }
    }
}

impl Default for XXH3_128 {
    fn default() -> Self {
        Self::new()
    }
}

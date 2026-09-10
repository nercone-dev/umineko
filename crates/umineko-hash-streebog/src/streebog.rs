use core::fmt;

use umineko_helpers::provider::{HashProvider, HashProviderRequest, HashProviders, ProviderBackend};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Streebog {
    V256,
    V512,
}

impl Streebog {
    pub fn digest_size(&self) -> usize {
        match self {
            Self::V256 => 32,
            Self::V512 => 64,
        }
    }

    pub fn block_size(&self) -> usize {
        match self {
            Self::V256 => 64,
            Self::V512 => 64,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::V256 => "Streebog-256",
            Self::V512 => "Streebog-512",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "Streebog-256" => Some(Self::V256),
            "Streebog-512" => Some(Self::V512),
            _ => None,
        }
    }
}

impl fmt::Display for Streebog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug)]
pub struct Streebog256 {
    state: [u8; 64],
    counter: [u8; 64],
    sum: [u8; 64],
    buffer: [u8; 64],
    length: usize,
    backend: ProviderBackend<dyn HashProvider>,
}

impl Streebog256 {
    pub const NAME: &'static str = "Streebog-256";
    pub const DIGEST_SIZE: usize = 32;
    pub const BLOCK_SIZE: usize = 64;

    pub fn new() -> Self {
        match HashProviders::backend(&Self::request()) {
            ProviderBackend::Builtin => todo!(),
            backend => Self { state: [0; 64], counter: [0; 64], sum: [0; 64], buffer: [0; 64], length: 0, backend },
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

impl Clone for Streebog256 {
    fn clone(&self) -> Self {
        Self { state: self.state, counter: self.counter, sum: self.sum, buffer: self.buffer, length: self.length, backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)) }
    }
}

impl Default for Streebog256 {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct Streebog512 {
    state: [u8; 64],
    counter: [u8; 64],
    sum: [u8; 64],
    buffer: [u8; 64],
    length: usize,
    backend: ProviderBackend<dyn HashProvider>,
}

impl Streebog512 {
    pub const NAME: &'static str = "Streebog-512";
    pub const DIGEST_SIZE: usize = 64;
    pub const BLOCK_SIZE: usize = 64;

    pub fn new() -> Self {
        match HashProviders::backend(&Self::request()) {
            ProviderBackend::Builtin => todo!(),
            backend => Self { state: [0; 64], counter: [0; 64], sum: [0; 64], buffer: [0; 64], length: 0, backend },
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

    pub fn finalize(self) -> [u8; 64] {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => {
                let mut digest = [0; 64];
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

    pub fn digest(data: &[u8]) -> [u8; 64] {
        let mut digest = [0; 64];
        match HashProviders::digest(&Self::request(), data, &mut digest) {
            Some(_) => digest,
            None => todo!(),
        }
    }
}

impl Clone for Streebog512 {
    fn clone(&self) -> Self {
        Self { state: self.state, counter: self.counter, sum: self.sum, buffer: self.buffer, length: self.length, backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)) }
    }
}

impl Default for Streebog512 {
    fn default() -> Self {
        Self::new()
    }
}

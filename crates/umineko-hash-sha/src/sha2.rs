use core::fmt;

use umineko_helpers::provider::{HashProvider, HashProviderRequest, HashProviders, ProviderBackend};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SHA2 {
    V224,
    V256,
    V384,
    V512,
    V512_224,
    V512_256,
}

impl SHA2 {
    pub fn digest_size(&self) -> usize {
        match self {
            Self::V224 => 28,
            Self::V256 => 32,
            Self::V384 => 48,
            Self::V512 => 64,
            Self::V512_224 => 28,
            Self::V512_256 => 32,
        }
    }

    pub fn block_size(&self) -> usize {
        match self {
            Self::V224 => 64,
            Self::V256 => 64,
            Self::V384 => 128,
            Self::V512 => 128,
            Self::V512_224 => 128,
            Self::V512_256 => 128,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::V224 => "SHA-224",
            Self::V256 => "SHA-256",
            Self::V384 => "SHA-384",
            Self::V512 => "SHA-512",
            Self::V512_224 => "SHA-512/224",
            Self::V512_256 => "SHA-512/256",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "SHA-224" => Some(Self::V224),
            "SHA-256" => Some(Self::V256),
            "SHA-384" => Some(Self::V384),
            "SHA-512" => Some(Self::V512),
            "SHA-512/224" => Some(Self::V512_224),
            "SHA-512/256" => Some(Self::V512_256),
            _ => None,
        }
    }
}

impl fmt::Display for SHA2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug)]
pub struct SHA2_224 {
    state: [u32; 8],
    buffer: [u8; 64],
    length: u64,
    backend: ProviderBackend<dyn HashProvider>,
}

impl SHA2_224 {
    pub const NAME: &'static str = "SHA-224";
    pub const DIGEST_SIZE: usize = 28;
    pub const BLOCK_SIZE: usize = 64;

    pub fn new() -> Self {
        match HashProviders::backend(&Self::request()) {
            ProviderBackend::Builtin => todo!(),
            backend => Self { state: [0; 8], buffer: [0; 64], length: 0, backend },
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

    pub fn finalize(self) -> [u8; 28] {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => {
                let mut digest = [0; 28];
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

    pub fn digest(data: &[u8]) -> [u8; 28] {
        let mut digest = [0; 28];
        match HashProviders::digest(&Self::request(), data, &mut digest) {
            Some(_) => digest,
            None => todo!(),
        }
    }
}

impl Clone for SHA2_224 {
    fn clone(&self) -> Self {
        Self { state: self.state, buffer: self.buffer, length: self.length, backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)) }
    }
}

impl Default for SHA2_224 {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct SHA2_256 {
    state: [u32; 8],
    buffer: [u8; 64],
    length: u64,
    backend: ProviderBackend<dyn HashProvider>,
}

impl SHA2_256 {
    pub const NAME: &'static str = "SHA-256";
    pub const DIGEST_SIZE: usize = 32;
    pub const BLOCK_SIZE: usize = 64;

    pub fn new() -> Self {
        match HashProviders::backend(&Self::request()) {
            ProviderBackend::Builtin => todo!(),
            backend => Self { state: [0; 8], buffer: [0; 64], length: 0, backend },
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

impl Clone for SHA2_256 {
    fn clone(&self) -> Self {
        Self { state: self.state, buffer: self.buffer, length: self.length, backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)) }
    }
}

impl Default for SHA2_256 {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct SHA2_384 {
    state: [u64; 8],
    buffer: [u8; 128],
    length: u128,
    backend: ProviderBackend<dyn HashProvider>,
}

impl SHA2_384 {
    pub const NAME: &'static str = "SHA-384";
    pub const DIGEST_SIZE: usize = 48;
    pub const BLOCK_SIZE: usize = 128;

    pub fn new() -> Self {
        match HashProviders::backend(&Self::request()) {
            ProviderBackend::Builtin => todo!(),
            backend => Self { state: [0; 8], buffer: [0; 128], length: 0, backend },
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

    pub fn finalize(self) -> [u8; 48] {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => {
                let mut digest = [0; 48];
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

    pub fn digest(data: &[u8]) -> [u8; 48] {
        let mut digest = [0; 48];
        match HashProviders::digest(&Self::request(), data, &mut digest) {
            Some(_) => digest,
            None => todo!(),
        }
    }
}

impl Clone for SHA2_384 {
    fn clone(&self) -> Self {
        Self { state: self.state, buffer: self.buffer, length: self.length, backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)) }
    }
}

impl Default for SHA2_384 {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct SHA2_512 {
    state: [u64; 8],
    buffer: [u8; 128],
    length: u128,
    backend: ProviderBackend<dyn HashProvider>,
}

impl SHA2_512 {
    pub const NAME: &'static str = "SHA-512";
    pub const DIGEST_SIZE: usize = 64;
    pub const BLOCK_SIZE: usize = 128;

    pub fn new() -> Self {
        match HashProviders::backend(&Self::request()) {
            ProviderBackend::Builtin => todo!(),
            backend => Self { state: [0; 8], buffer: [0; 128], length: 0, backend },
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

impl Clone for SHA2_512 {
    fn clone(&self) -> Self {
        Self { state: self.state, buffer: self.buffer, length: self.length, backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)) }
    }
}

impl Default for SHA2_512 {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct SHA2_512_224 {
    state: [u64; 8],
    buffer: [u8; 128],
    length: u128,
    backend: ProviderBackend<dyn HashProvider>,
}

impl SHA2_512_224 {
    pub const NAME: &'static str = "SHA-512/224";
    pub const DIGEST_SIZE: usize = 28;
    pub const BLOCK_SIZE: usize = 128;

    pub fn new() -> Self {
        match HashProviders::backend(&Self::request()) {
            ProviderBackend::Builtin => todo!(),
            backend => Self { state: [0; 8], buffer: [0; 128], length: 0, backend },
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

    pub fn finalize(self) -> [u8; 28] {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => {
                let mut digest = [0; 28];
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

    pub fn digest(data: &[u8]) -> [u8; 28] {
        let mut digest = [0; 28];
        match HashProviders::digest(&Self::request(), data, &mut digest) {
            Some(_) => digest,
            None => todo!(),
        }
    }
}

impl Clone for SHA2_512_224 {
    fn clone(&self) -> Self {
        Self { state: self.state, buffer: self.buffer, length: self.length, backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)) }
    }
}

impl Default for SHA2_512_224 {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct SHA2_512_256 {
    state: [u64; 8],
    buffer: [u8; 128],
    length: u128,
    backend: ProviderBackend<dyn HashProvider>,
}

impl SHA2_512_256 {
    pub const NAME: &'static str = "SHA-512/256";
    pub const DIGEST_SIZE: usize = 32;
    pub const BLOCK_SIZE: usize = 128;

    pub fn new() -> Self {
        match HashProviders::backend(&Self::request()) {
            ProviderBackend::Builtin => todo!(),
            backend => Self { state: [0; 8], buffer: [0; 128], length: 0, backend },
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

impl Clone for SHA2_512_256 {
    fn clone(&self) -> Self {
        Self { state: self.state, buffer: self.buffer, length: self.length, backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)) }
    }
}

impl Default for SHA2_512_256 {
    fn default() -> Self {
        Self::new()
    }
}

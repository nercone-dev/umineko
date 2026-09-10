use core::fmt;

use umineko_helpers::provider::{HashProvider, HashProviderRequest, HashProviders, ProviderBackend};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SHA3 {
    V224,
    V256,
    V384,
    V512,
}

impl SHA3 {
    pub fn digest_size(&self) -> usize {
        match self {
            Self::V224 => 28,
            Self::V256 => 32,
            Self::V384 => 48,
            Self::V512 => 64,
        }
    }

    pub fn block_size(&self) -> usize {
        match self {
            Self::V224 => 144,
            Self::V256 => 136,
            Self::V384 => 104,
            Self::V512 => 72,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::V224 => "SHA3-224",
            Self::V256 => "SHA3-256",
            Self::V384 => "SHA3-384",
            Self::V512 => "SHA3-512",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "SHA3-224" => Some(Self::V224),
            "SHA3-256" => Some(Self::V256),
            "SHA3-384" => Some(Self::V384),
            "SHA3-512" => Some(Self::V512),
            _ => None,
        }
    }
}

impl fmt::Display for SHA3 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug)]
pub struct SHA3_224 {
    state: [u64; 25],
    buffer: [u8; 144],
    length: usize,
    backend: ProviderBackend<dyn HashProvider>,
}

impl SHA3_224 {
    pub const NAME: &'static str = "SHA3-224";
    pub const DIGEST_SIZE: usize = 28;
    pub const BLOCK_SIZE: usize = 144;

    pub fn new() -> Self {
        match HashProviders::backend(&Self::request()) {
            ProviderBackend::Builtin => todo!(),
            backend => Self { state: [0; 25], buffer: [0; 144], length: 0, backend },
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

impl Clone for SHA3_224 {
    fn clone(&self) -> Self {
        Self { state: self.state, buffer: self.buffer, length: self.length, backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)) }
    }
}

impl Default for SHA3_224 {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct SHA3_256 {
    state: [u64; 25],
    buffer: [u8; 136],
    length: usize,
    backend: ProviderBackend<dyn HashProvider>,
}

impl SHA3_256 {
    pub const NAME: &'static str = "SHA3-256";
    pub const DIGEST_SIZE: usize = 32;
    pub const BLOCK_SIZE: usize = 136;

    pub fn new() -> Self {
        match HashProviders::backend(&Self::request()) {
            ProviderBackend::Builtin => todo!(),
            backend => Self { state: [0; 25], buffer: [0; 136], length: 0, backend },
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

impl Clone for SHA3_256 {
    fn clone(&self) -> Self {
        Self { state: self.state, buffer: self.buffer, length: self.length, backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)) }
    }
}

impl Default for SHA3_256 {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct SHA3_384 {
    state: [u64; 25],
    buffer: [u8; 104],
    length: usize,
    backend: ProviderBackend<dyn HashProvider>,
}

impl SHA3_384 {
    pub const NAME: &'static str = "SHA3-384";
    pub const DIGEST_SIZE: usize = 48;
    pub const BLOCK_SIZE: usize = 104;

    pub fn new() -> Self {
        match HashProviders::backend(&Self::request()) {
            ProviderBackend::Builtin => todo!(),
            backend => Self { state: [0; 25], buffer: [0; 104], length: 0, backend },
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

impl Clone for SHA3_384 {
    fn clone(&self) -> Self {
        Self { state: self.state, buffer: self.buffer, length: self.length, backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)) }
    }
}

impl Default for SHA3_384 {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct SHA3_512 {
    state: [u64; 25],
    buffer: [u8; 72],
    length: usize,
    backend: ProviderBackend<dyn HashProvider>,
}

impl SHA3_512 {
    pub const NAME: &'static str = "SHA3-512";
    pub const DIGEST_SIZE: usize = 64;
    pub const BLOCK_SIZE: usize = 72;

    pub fn new() -> Self {
        match HashProviders::backend(&Self::request()) {
            ProviderBackend::Builtin => todo!(),
            backend => Self { state: [0; 25], buffer: [0; 72], length: 0, backend },
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

impl Clone for SHA3_512 {
    fn clone(&self) -> Self {
        Self { state: self.state, buffer: self.buffer, length: self.length, backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)) }
    }
}

impl Default for SHA3_512 {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SHAKE {
    V128,
    V256,
}

impl SHAKE {
    pub fn digest_size(&self) -> usize {
        match self {
            Self::V128 => 32,
            Self::V256 => 64,
        }
    }

    pub fn block_size(&self) -> usize {
        match self {
            Self::V128 => 168,
            Self::V256 => 136,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::V128 => "SHAKE128",
            Self::V256 => "SHAKE256",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "SHAKE128" => Some(Self::V128),
            "SHAKE256" => Some(Self::V256),
            _ => None,
        }
    }
}

impl fmt::Display for SHAKE {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug)]
pub struct SHAKE128 {
    state: [u64; 25],
    buffer: [u8; 168],
    length: usize,
    backend: ProviderBackend<dyn HashProvider>,
}

impl SHAKE128 {
    pub const NAME: &'static str = "SHAKE128";
    pub const BLOCK_SIZE: usize = 168;

    pub fn new() -> Self {
        match HashProviders::backend(&Self::request()) {
            ProviderBackend::Builtin => todo!(),
            backend => Self { state: [0; 25], buffer: [0; 168], length: 0, backend },
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

impl Clone for SHAKE128 {
    fn clone(&self) -> Self {
        Self { state: self.state, buffer: self.buffer, length: self.length, backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)) }
    }
}

#[derive(Debug)]
pub struct SHAKE256 {
    state: [u64; 25],
    buffer: [u8; 136],
    length: usize,
    backend: ProviderBackend<dyn HashProvider>,
}

impl SHAKE256 {
    pub const NAME: &'static str = "SHAKE256";
    pub const BLOCK_SIZE: usize = 136;

    pub fn new() -> Self {
        match HashProviders::backend(&Self::request()) {
            ProviderBackend::Builtin => todo!(),
            backend => Self { state: [0; 25], buffer: [0; 136], length: 0, backend },
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

impl Clone for SHAKE256 {
    fn clone(&self) -> Self {
        Self { state: self.state, buffer: self.buffer, length: self.length, backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)) }
    }
}

impl Default for SHAKE128 {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for SHAKE256 {
    fn default() -> Self {
        Self::new()
    }
}

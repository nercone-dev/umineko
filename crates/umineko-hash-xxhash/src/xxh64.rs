use umineko_helpers::provider::{HashProvider, HashProviderRequest, HashProviders, ProviderBackend};

#[derive(Debug)]
pub struct XXH64 {
    state: [u64; 4],
    buffer: [u8; 32],
    length: u64,
    seed: u64,
    backend: ProviderBackend<dyn HashProvider>,
}

impl XXH64 {
    pub const NAME: &'static str = "XXH64";
    pub const DIGEST_SIZE: usize = 8;
    pub const BLOCK_SIZE: usize = 32;

    pub fn new() -> Self {
        match HashProviders::backend(&Self::request()) {
            ProviderBackend::Builtin => todo!(),
            backend => Self { state: [0; 4], buffer: [0; 32], length: 0, seed: 0, backend },
        }
    }

    pub fn request() -> HashProviderRequest<'static> {
        HashProviderRequest::new(Self::NAME)
    }

    pub fn with_seed(seed: u64) -> Self {
        match HashProviders::backend(&Self::request().with_seed(seed)) {
            ProviderBackend::Builtin => todo!(),
            backend => Self { state: [0; 4], buffer: [0; 32], length: 0, seed, backend },
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

impl Clone for XXH64 {
    fn clone(&self) -> Self {
        Self { state: self.state, buffer: self.buffer, length: self.length, seed: self.seed, backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)) }
    }
}

impl Default for XXH64 {
    fn default() -> Self {
        Self::new()
    }
}

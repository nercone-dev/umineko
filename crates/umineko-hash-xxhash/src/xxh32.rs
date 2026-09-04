use umineko_helpers::provider::{HashProvider, HashProviderRequest, HashProviders, ProviderBackend};

#[derive(Debug)]
pub struct XXH32 {
    state: [u32; 4],
    buffer: [u8; 16],
    length: u64,
    seed: u32,
    backend: ProviderBackend<dyn HashProvider>,
}

impl XXH32 {
    pub const NAME: &'static str = "XXH32";
    pub const DIGEST_SIZE: usize = 4;
    pub const BLOCK_SIZE: usize = 16;

    pub fn new() -> Self {
        match HashProviders::backend(&Self::request()) {
            ProviderBackend::Builtin => todo!(),
            backend => Self { state: [0; 4], buffer: [0; 16], length: 0, seed: 0, backend },
        }
    }

    pub fn request() -> HashProviderRequest<'static> {
        HashProviderRequest::new(Self::NAME)
    }

    pub fn with_seed(seed: u32) -> Self {
        match HashProviders::backend(&Self::request().with_seed(seed.into())) {
            ProviderBackend::Builtin => todo!(),
            backend => Self { state: [0; 4], buffer: [0; 16], length: 0, seed, backend },
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => provider.update(*handle, data),
        }
    }

    pub fn finalize(self) -> [u8; 4] {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => {
                let mut digest = [0; 4];
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

    pub fn digest(data: &[u8]) -> [u8; 4] {
        let mut digest = [0; 4];
        match HashProviders::digest(&Self::request(), data, &mut digest) {
            Some(_) => digest,
            None => todo!(),
        }
    }
}

impl Clone for XXH32 {
    fn clone(&self) -> Self {
        Self { state: self.state, buffer: self.buffer, length: self.length, seed: self.seed, backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)) }
    }
}

impl Default for XXH32 {
    fn default() -> Self {
        Self::new()
    }
}

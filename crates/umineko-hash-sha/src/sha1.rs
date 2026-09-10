use umineko_helpers::provider::{HashProvider, HashProviderRequest, HashProviders, ProviderBackend};

#[derive(Debug)]
pub struct SHA1 {
    state: [u32; 5],
    buffer: [u8; 64],
    length: u64,
    backend: ProviderBackend<dyn HashProvider>,
}

impl SHA1 {
    pub const NAME: &'static str = "SHA-1";
    pub const DIGEST_SIZE: usize = 20;
    pub const BLOCK_SIZE: usize = 64;

    pub fn new() -> Self {
        match HashProviders::backend(&Self::request()) {
            ProviderBackend::Builtin => todo!(),
            backend => Self { state: [0; 5], buffer: [0; 64], length: 0, backend },
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

    pub fn finalize(self) -> [u8; 20] {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => {
                let mut digest = [0; 20];
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

    pub fn digest(data: &[u8]) -> [u8; 20] {
        let mut digest = [0; 20];
        match HashProviders::digest(&Self::request(), data, &mut digest) {
            Some(_) => digest,
            None => todo!(),
        }
    }
}

impl Clone for SHA1 {
    fn clone(&self) -> Self {
        Self { state: self.state, buffer: self.buffer, length: self.length, backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)) }
    }
}

impl Default for SHA1 {
    fn default() -> Self {
        Self::new()
    }
}

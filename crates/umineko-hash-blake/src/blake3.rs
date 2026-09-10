use umineko_helpers::provider::{HashProvider, HashProviderRequest, HashProviders, ProviderBackend};

#[derive(Debug)]
pub struct BLAKE3 {
    chunk: [u32; 8],
    stack: [[u32; 8]; 54],
    buffer: [u8; 64],
    length: u64,
    backend: ProviderBackend<dyn HashProvider>,
}

impl BLAKE3 {
    pub const NAME: &'static str = "BLAKE3";
    pub const BLOCK_SIZE: usize = 64;

    pub fn new() -> Self {
        match HashProviders::backend(&Self::request()) {
            ProviderBackend::Builtin => todo!(),
            backend => Self { chunk: [0; 8], stack: [[0; 8]; 54], buffer: [0; 64], length: 0, backend },
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
    pub fn with_key(key: &[u8; 32]) -> Self {
        match HashProviders::backend(&Self::request().with_key(key)) {
            ProviderBackend::Builtin => todo!(),
            backend => Self { chunk: [0; 8], stack: [[0; 8]; 54], buffer: [0; 64], length: 0, backend },
        }
    }
    pub fn with_context(context: &str) -> Self {
        match HashProviders::backend(&Self::request().with_customization(context.as_bytes())) {
            ProviderBackend::Builtin => todo!(),
            backend => Self { chunk: [0; 8], stack: [[0; 8]; 54], buffer: [0; 64], length: 0, backend },
        }
    }
}

impl Clone for BLAKE3 {
    fn clone(&self) -> Self {
        Self { chunk: self.chunk, stack: self.stack, buffer: self.buffer, length: self.length, backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)) }
    }
}

impl Default for BLAKE3 {
    fn default() -> Self {
        Self::new()
    }
}

use umineko_helpers::provider::{HashProvider, HashProviderRequest, HashProviders, ProviderBackend};

#[derive(Debug)]
pub struct MD6 {
    state: [u64; 16],
    buffer: [u8; 512],
    length: u64,
    digest_size: usize,
    backend: ProviderBackend<dyn HashProvider>,
}

impl MD6 {
    pub const NAME: &'static str = "MD6";
    pub const BLOCK_SIZE: usize = 512;

    pub fn new(digest_size: usize) -> Self {
        match HashProviders::backend(&Self::request(digest_size)) {
            ProviderBackend::Builtin => todo!(),
            backend => Self { state: [0; 16], buffer: [0; 512], length: 0, digest_size, backend },
        }
    }

    pub fn with_key(digest_size: usize, key: &[u8]) -> Self {
        match HashProviders::backend(&Self::request(digest_size).with_key(key)) {
            ProviderBackend::Builtin => todo!(),
            backend => Self { state: [0; 16], buffer: [0; 512], length: 0, digest_size, backend },
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

impl Clone for MD6 {
    fn clone(&self) -> Self {
        Self { state: self.state, buffer: self.buffer, length: self.length, digest_size: self.digest_size, backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)) }
    }
}

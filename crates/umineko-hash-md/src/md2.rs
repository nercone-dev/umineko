use umineko_helpers::provider::{HashProvider, HashProviderRequest, HashProviders, ProviderBackend};

#[derive(Debug)]
pub struct MD2 {
    state: [u8; 48],
    checksum: [u8; 16],
    buffer: [u8; 16],
    length: usize,
    backend: ProviderBackend<dyn HashProvider>,
}

impl MD2 {
    pub const NAME: &'static str = "MD2";
    pub const DIGEST_SIZE: usize = 16;
    pub const BLOCK_SIZE: usize = 16;

    pub fn new() -> Self {
        match HashProviders::backend(&Self::request()) {
            ProviderBackend::Builtin => todo!(),
            backend => Self { state: [0; 48], checksum: [0; 16], buffer: [0; 16], length: 0, backend },
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

impl Clone for MD2 {
    fn clone(&self) -> Self {
        Self { state: self.state, checksum: self.checksum, buffer: self.buffer, length: self.length, backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)) }
    }
}

impl Default for MD2 {
    fn default() -> Self {
        Self::new()
    }
}

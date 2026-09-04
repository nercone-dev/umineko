use umineko_helpers::provider::{HashProvider, HashProviderRequest, HashProviders, ProviderBackend};

#[derive(Debug)]
pub struct CRC32C {
    value: u32,
    backend: ProviderBackend<dyn HashProvider>,
}

impl CRC32C {
    pub const NAME: &'static str = "CRC-32C";
    pub const DIGEST_SIZE: usize = 4;
    pub const POLYNOMIAL: u32 = 0x1EDC_6F41;

    pub fn new() -> Self {
        match HashProviders::backend(&Self::request()) {
            ProviderBackend::Builtin => todo!(),
            backend => Self { value: 0, backend },
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

    pub fn finalize(self) -> u32 {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => {
                let mut digest = [0; Self::DIGEST_SIZE];
                provider.finalize(*handle, &mut digest);
                u32::from_be_bytes(digest)
            }
        }
    }

    pub fn reset(&mut self) {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => provider.reset(*handle),
        }
    }

    pub fn digest(data: &[u8]) -> u32 {
        let mut digest = [0; Self::DIGEST_SIZE];
        match HashProviders::digest(&Self::request(), data, &mut digest) {
            Some(_) => u32::from_be_bytes(digest),
            None => todo!(),
        }
    }
}

impl Clone for CRC32C {
    fn clone(&self) -> Self {
        Self { value: self.value, backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)) }
    }
}

impl Default for CRC32C {
    fn default() -> Self {
        Self::new()
    }
}

use crate::errors::Poly1305Error;

use umineko_helpers::provider::{HashProvider, HashProviderRequest, HashProviders, ProviderBackend};

#[derive(Debug)]
pub struct Poly1305 {
    accumulator: [u32; 5],
    r: [u32; 5],
    s: [u32; 4],
    buffer: [u8; 16],
    length: usize,
    backend: ProviderBackend<dyn HashProvider>,
}

impl Poly1305 {
    pub const NAME: &'static str = "Poly1305";
    pub const KEY_SIZE: usize = 32;
    pub const TAG_SIZE: usize = 16;
    pub const BLOCK_SIZE: usize = 16;

    pub fn new(key: &[u8; 32]) -> Self {
        match HashProviders::backend(&Self::request(key)) {
            ProviderBackend::Builtin => todo!(),
            backend => Self { accumulator: [0; 5], r: [0; 5], s: [0; 4], buffer: [0; 16], length: 0, backend },
        }
    }

    pub fn request(key: &[u8; 32]) -> HashProviderRequest<'_> {
        HashProviderRequest::new(Self::NAME).with_key(key)
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
                let mut tag = [0; 16];
                provider.finalize(*handle, &mut tag);
                tag
            }
        }
    }

    pub fn verify(self, tag: &[u8; 16]) -> Result<(), Poly1305Error> {
        let computed = self.finalize();
        let mut difference = 0;
        for (left, right) in computed.iter().zip(tag) {
            difference |= left ^ right;
        }
        match difference {
            0 => Ok(()),
            _ => Err(Poly1305Error::Authentication),
        }
    }

    pub fn tag(key: &[u8; 32], data: &[u8]) -> [u8; 16] {
        let mut tag = [0; 16];
        match HashProviders::digest(&Self::request(key), data, &mut tag) {
            Some(_) => tag,
            None => todo!(),
        }
    }
}

impl Clone for Poly1305 {
    fn clone(&self) -> Self {
        Self { accumulator: self.accumulator, r: self.r, s: self.s, buffer: self.buffer, length: self.length, backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)) }
    }
}

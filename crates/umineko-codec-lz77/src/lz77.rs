use alloc::vec::Vec;
use crate::errors::LZ77Error;

use umineko_helpers::provider::{CodecDirection, CodecProvider, CodecProviderRequest, CodecProviders, ProviderBackend};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LZ77 {
    pub window: usize,
    pub lookahead: usize,
        pub limit: Option<usize>,
}

impl Default for LZ77 {
    fn default() -> Self {
        Self {
            window: 32 * 1024,
            lookahead: 258,
            limit: None,
        }
    }
}

impl LZ77 {
    pub const NAME: &'static str = "lz77";

    pub fn request(&self, direction: CodecDirection) -> CodecProviderRequest<'_> {
        CodecProviderRequest::new(Self::NAME, direction).with_limit(self.limit)
    }

    pub fn encoder(&self) -> LZ77Encoder {
        LZ77Encoder::new(self.clone())
    }

    pub fn decoder(&self) -> LZ77Decoder {
        LZ77Decoder::new(self.clone())
    }

    pub fn compress(&self, data: &[u8]) -> Result<Vec<u8>, LZ77Error> {
        match CodecProviders::transform(&self.request(CodecDirection::Encode), data)? {
            Some(output) => Ok(output),
            None => todo!(),
        }
    }

    pub fn decompress(&self, data: &[u8]) -> Result<Vec<u8>, LZ77Error> {
        match CodecProviders::transform(&self.request(CodecDirection::Decode), data)? {
            Some(output) => Ok(output),
            None => todo!(),
        }
    }
}

#[derive(Debug)]
pub struct LZ77Encoder {
    options: LZ77,
    backend: ProviderBackend<dyn CodecProvider>,
}

impl LZ77Encoder {
    pub fn new(options: LZ77) -> Self {
        match CodecProviders::backend(&options.request(CodecDirection::Encode)) {
            ProviderBackend::Builtin => todo!(),
            backend => Self { options, backend },
        }
    }

    pub fn options(&self) -> &LZ77 {
        &self.options
    }

    pub fn update(&mut self, data: &[u8]) -> Result<Vec<u8>, LZ77Error> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => Ok(provider.update(*handle, data)?),
        }
    }

    pub fn finalize(self) -> Result<Vec<u8>, LZ77Error> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => Ok(provider.finalize(*handle)?),
        }
    }

    pub fn reset(&mut self) {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => provider.reset(*handle),
        }
    }
}

#[derive(Debug)]
pub struct LZ77Decoder {
    options: LZ77,
    backend: ProviderBackend<dyn CodecProvider>,
}

impl LZ77Decoder {
    pub fn new(options: LZ77) -> Self {
        match CodecProviders::backend(&options.request(CodecDirection::Decode)) {
            ProviderBackend::Builtin => todo!(),
            backend => Self { options, backend },
        }
    }

    pub fn options(&self) -> &LZ77 {
        &self.options
    }

    pub fn update(&mut self, data: &[u8]) -> Result<Vec<u8>, LZ77Error> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => Ok(provider.update(*handle, data)?),
        }
    }

    pub fn finalize(self) -> Result<Vec<u8>, LZ77Error> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => Ok(provider.finalize(*handle)?),
        }
    }

    pub fn reset(&mut self) {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => provider.reset(*handle),
        }
    }
}

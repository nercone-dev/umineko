use alloc::vec::Vec;
use crate::errors::LZ78Error;

use umineko_helpers::provider::{CodecDirection, CodecProvider, CodecProviderRequest, CodecProviders, ProviderBackend};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LZ78 {
    pub dictionary: usize,
        pub limit: Option<usize>,
}

impl Default for LZ78 {
    fn default() -> Self {
        Self {
            dictionary: 64 * 1024,
            limit: None,
        }
    }
}

impl LZ78 {
    pub const NAME: &'static str = "lz78";

    pub fn request(&self, direction: CodecDirection) -> CodecProviderRequest<'_> {
        CodecProviderRequest::new(Self::NAME, direction).with_limit(self.limit)
    }

    pub fn encoder(&self) -> LZ78Encoder {
        LZ78Encoder::new(self.clone())
    }

    pub fn decoder(&self) -> LZ78Decoder {
        LZ78Decoder::new(self.clone())
    }

    pub fn compress(&self, data: &[u8]) -> Result<Vec<u8>, LZ78Error> {
        match CodecProviders::transform(&self.request(CodecDirection::Encode), data)? {
            Some(output) => Ok(output),
            None => todo!(),
        }
    }

    pub fn decompress(&self, data: &[u8]) -> Result<Vec<u8>, LZ78Error> {
        match CodecProviders::transform(&self.request(CodecDirection::Decode), data)? {
            Some(output) => Ok(output),
            None => todo!(),
        }
    }
}

#[derive(Debug)]
pub struct LZ78Encoder {
    options: LZ78,
    backend: ProviderBackend<dyn CodecProvider>,
}

impl LZ78Encoder {
    pub fn new(options: LZ78) -> Self {
        match CodecProviders::backend(&options.request(CodecDirection::Encode)) {
            ProviderBackend::Builtin => todo!(),
            backend => Self { options, backend },
        }
    }

    pub fn options(&self) -> &LZ78 {
        &self.options
    }

    pub fn update(&mut self, data: &[u8]) -> Result<Vec<u8>, LZ78Error> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => Ok(provider.update(*handle, data)?),
        }
    }

    pub fn finalize(self) -> Result<Vec<u8>, LZ78Error> {
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
pub struct LZ78Decoder {
    options: LZ78,
    backend: ProviderBackend<dyn CodecProvider>,
}

impl LZ78Decoder {
    pub fn new(options: LZ78) -> Self {
        match CodecProviders::backend(&options.request(CodecDirection::Decode)) {
            ProviderBackend::Builtin => todo!(),
            backend => Self { options, backend },
        }
    }

    pub fn options(&self) -> &LZ78 {
        &self.options
    }

    pub fn update(&mut self, data: &[u8]) -> Result<Vec<u8>, LZ78Error> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => Ok(provider.update(*handle, data)?),
        }
    }

    pub fn finalize(self) -> Result<Vec<u8>, LZ78Error> {
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

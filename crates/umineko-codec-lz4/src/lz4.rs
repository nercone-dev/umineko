use alloc::vec::Vec;
use crate::errors::LZ4Error;

use umineko_helpers::provider::{CodecDirection, CodecProvider, CodecProviderRequest, CodecProviders, ProviderBackend};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LZ4 {
    pub level: u8,
        pub limit: Option<usize>,
}

impl Default for LZ4 {
    fn default() -> Self {
        Self {
            level: 1,
            limit: None,
        }
    }
}

impl LZ4 {
    pub const NAME: &'static str = "lz4";

    pub fn request(&self, direction: CodecDirection) -> CodecProviderRequest<'_> {
        CodecProviderRequest::new(Self::NAME, direction).with_level(self.level as i32).with_limit(self.limit)
    }

    pub fn encoder(&self) -> LZ4Encoder {
        LZ4Encoder::new(self.clone())
    }

    pub fn decoder(&self) -> LZ4Decoder {
        LZ4Decoder::new(self.clone())
    }

    pub fn compress(&self, data: &[u8]) -> Result<Vec<u8>, LZ4Error> {
        match CodecProviders::transform(&self.request(CodecDirection::Encode), data)? {
            Some(output) => Ok(output),
            None => todo!(),
        }
    }

    pub fn decompress(&self, data: &[u8]) -> Result<Vec<u8>, LZ4Error> {
        match CodecProviders::transform(&self.request(CodecDirection::Decode), data)? {
            Some(output) => Ok(output),
            None => todo!(),
        }
    }
}

#[derive(Debug)]
pub struct LZ4Encoder {
    options: LZ4,
    backend: ProviderBackend<dyn CodecProvider>,
}

impl LZ4Encoder {
    pub fn new(options: LZ4) -> Self {
        match CodecProviders::backend(&options.request(CodecDirection::Encode)) {
            ProviderBackend::Builtin => todo!(),
            backend => Self { options, backend },
        }
    }

    pub fn options(&self) -> &LZ4 {
        &self.options
    }

    pub fn update(&mut self, data: &[u8]) -> Result<Vec<u8>, LZ4Error> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => Ok(provider.update(*handle, data)?),
        }
    }

    pub fn finalize(self) -> Result<Vec<u8>, LZ4Error> {
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
pub struct LZ4Decoder {
    options: LZ4,
    backend: ProviderBackend<dyn CodecProvider>,
}

impl LZ4Decoder {
    pub fn new(options: LZ4) -> Self {
        match CodecProviders::backend(&options.request(CodecDirection::Decode)) {
            ProviderBackend::Builtin => todo!(),
            backend => Self { options, backend },
        }
    }

    pub fn options(&self) -> &LZ4 {
        &self.options
    }

    pub fn update(&mut self, data: &[u8]) -> Result<Vec<u8>, LZ4Error> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => Ok(provider.update(*handle, data)?),
        }
    }

    pub fn finalize(self) -> Result<Vec<u8>, LZ4Error> {
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

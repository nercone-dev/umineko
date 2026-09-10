use alloc::vec::Vec;
use crate::errors::DeflateError;

use umineko_helpers::provider::{CodecDirection, CodecProvider, CodecProviderRequest, CodecProviders, ProviderBackend};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deflate {
    pub level: u8,
    pub window: u8,
        pub limit: Option<usize>,
}

impl Default for Deflate {
    fn default() -> Self {
        Self {
            level: 6,
            window: 15,
            limit: None,
        }
    }
}

impl Deflate {
    pub const NAME: &'static str = "deflate";

    pub fn request(&self, direction: CodecDirection) -> CodecProviderRequest<'_> {
        CodecProviderRequest::new(Self::NAME, direction).with_level(self.level as i32).with_window(self.window).with_limit(self.limit)
    }

    pub fn encoder(&self) -> DeflateEncoder {
        DeflateEncoder::new(self.clone())
    }

    pub fn decoder(&self) -> DeflateDecoder {
        DeflateDecoder::new(self.clone())
    }

    pub fn compress(&self, data: &[u8]) -> Result<Vec<u8>, DeflateError> {
        match CodecProviders::transform(&self.request(CodecDirection::Encode), data)? {
            Some(output) => Ok(output),
            None => todo!(),
        }
    }

    pub fn decompress(&self, data: &[u8]) -> Result<Vec<u8>, DeflateError> {
        match CodecProviders::transform(&self.request(CodecDirection::Decode), data)? {
            Some(output) => Ok(output),
            None => todo!(),
        }
    }
}

#[derive(Debug)]
pub struct DeflateEncoder {
    options: Deflate,
    backend: ProviderBackend<dyn CodecProvider>,
}

impl DeflateEncoder {
    pub fn new(options: Deflate) -> Self {
        match CodecProviders::backend(&options.request(CodecDirection::Encode)) {
            ProviderBackend::Builtin => todo!(),
            backend => Self { options, backend },
        }
    }

    pub fn options(&self) -> &Deflate {
        &self.options
    }

    pub fn update(&mut self, data: &[u8]) -> Result<Vec<u8>, DeflateError> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => Ok(provider.update(*handle, data)?),
        }
    }

    pub fn finalize(self) -> Result<Vec<u8>, DeflateError> {
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
pub struct DeflateDecoder {
    options: Deflate,
    backend: ProviderBackend<dyn CodecProvider>,
}

impl DeflateDecoder {
    pub fn new(options: Deflate) -> Self {
        match CodecProviders::backend(&options.request(CodecDirection::Decode)) {
            ProviderBackend::Builtin => todo!(),
            backend => Self { options, backend },
        }
    }

    pub fn options(&self) -> &Deflate {
        &self.options
    }

    pub fn update(&mut self, data: &[u8]) -> Result<Vec<u8>, DeflateError> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => Ok(provider.update(*handle, data)?),
        }
    }

    pub fn finalize(self) -> Result<Vec<u8>, DeflateError> {
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

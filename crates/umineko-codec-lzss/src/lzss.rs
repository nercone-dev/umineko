use alloc::vec::Vec;
use crate::errors::LZSSError;

use umineko_helpers::provider::{CodecDirection, CodecProvider, CodecProviderRequest, CodecProviders, ProviderBackend};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LZSS {
    pub window: usize,
    pub lookahead: usize,
    pub threshold: usize,
        pub limit: Option<usize>,
}

impl Default for LZSS {
    fn default() -> Self {
        Self {
            window: 4 * 1024,
            lookahead: 18,
            threshold: 3,
            limit: None,
        }
    }
}

impl LZSS {
    pub const NAME: &'static str = "lzss";

    pub fn request(&self, direction: CodecDirection) -> CodecProviderRequest<'_> {
        CodecProviderRequest::new(Self::NAME, direction).with_limit(self.limit)
    }

    pub fn encoder(&self) -> LZSSEncoder {
        LZSSEncoder::new(self.clone())
    }

    pub fn decoder(&self) -> LZSSDecoder {
        LZSSDecoder::new(self.clone())
    }

    pub fn compress(&self, data: &[u8]) -> Result<Vec<u8>, LZSSError> {
        match CodecProviders::transform(&self.request(CodecDirection::Encode), data)? {
            Some(output) => Ok(output),
            None => todo!(),
        }
    }

    pub fn decompress(&self, data: &[u8]) -> Result<Vec<u8>, LZSSError> {
        match CodecProviders::transform(&self.request(CodecDirection::Decode), data)? {
            Some(output) => Ok(output),
            None => todo!(),
        }
    }
}

#[derive(Debug)]
pub struct LZSSEncoder {
    options: LZSS,
    backend: ProviderBackend<dyn CodecProvider>,
}

impl LZSSEncoder {
    pub fn new(options: LZSS) -> Self {
        match CodecProviders::backend(&options.request(CodecDirection::Encode)) {
            ProviderBackend::Builtin => todo!(),
            backend => Self { options, backend },
        }
    }

    pub fn options(&self) -> &LZSS {
        &self.options
    }

    pub fn update(&mut self, data: &[u8]) -> Result<Vec<u8>, LZSSError> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => Ok(provider.update(*handle, data)?),
        }
    }

    pub fn finalize(self) -> Result<Vec<u8>, LZSSError> {
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
pub struct LZSSDecoder {
    options: LZSS,
    backend: ProviderBackend<dyn CodecProvider>,
}

impl LZSSDecoder {
    pub fn new(options: LZSS) -> Self {
        match CodecProviders::backend(&options.request(CodecDirection::Decode)) {
            ProviderBackend::Builtin => todo!(),
            backend => Self { options, backend },
        }
    }

    pub fn options(&self) -> &LZSS {
        &self.options
    }

    pub fn update(&mut self, data: &[u8]) -> Result<Vec<u8>, LZSSError> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => Ok(provider.update(*handle, data)?),
        }
    }

    pub fn finalize(self) -> Result<Vec<u8>, LZSSError> {
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

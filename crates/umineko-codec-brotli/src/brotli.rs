use alloc::vec::Vec;
use crate::errors::BrotliError;

use umineko_helpers::provider::{CodecDirection, CodecProvider, CodecProviderRequest, CodecProviders, ProviderBackend};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Brotli {
    pub quality: u8,
    pub window: u8,
        pub limit: Option<usize>,
}

impl Default for Brotli {
    fn default() -> Self {
        Self {
            quality: 11,
            window: 22,
            limit: None,
        }
    }
}

impl Brotli {
    pub const NAME: &'static str = "brotli";

    pub fn request(&self, direction: CodecDirection) -> CodecProviderRequest<'_> {
        CodecProviderRequest::new(Self::NAME, direction).with_level(self.quality as i32).with_window(self.window).with_limit(self.limit)
    }

    pub fn encoder(&self) -> BrotliEncoder {
        BrotliEncoder::new(self.clone())
    }

    pub fn decoder(&self) -> BrotliDecoder {
        BrotliDecoder::new(self.clone())
    }

    pub fn compress(&self, data: &[u8]) -> Result<Vec<u8>, BrotliError> {
        match CodecProviders::transform(&self.request(CodecDirection::Encode), data)? {
            Some(output) => Ok(output),
            None => todo!(),
        }
    }

    pub fn decompress(&self, data: &[u8]) -> Result<Vec<u8>, BrotliError> {
        match CodecProviders::transform(&self.request(CodecDirection::Decode), data)? {
            Some(output) => Ok(output),
            None => todo!(),
        }
    }
}

#[derive(Debug)]
pub struct BrotliEncoder {
    options: Brotli,
    backend: ProviderBackend<dyn CodecProvider>,
}

impl BrotliEncoder {
    pub fn new(options: Brotli) -> Self {
        match CodecProviders::backend(&options.request(CodecDirection::Encode)) {
            ProviderBackend::Builtin => todo!(),
            backend => Self { options, backend },
        }
    }

    pub fn options(&self) -> &Brotli {
        &self.options
    }

    pub fn update(&mut self, data: &[u8]) -> Result<Vec<u8>, BrotliError> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => Ok(provider.update(*handle, data)?),
        }
    }

    pub fn finalize(self) -> Result<Vec<u8>, BrotliError> {
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
pub struct BrotliDecoder {
    options: Brotli,
    backend: ProviderBackend<dyn CodecProvider>,
}

impl BrotliDecoder {
    pub fn new(options: Brotli) -> Self {
        match CodecProviders::backend(&options.request(CodecDirection::Decode)) {
            ProviderBackend::Builtin => todo!(),
            backend => Self { options, backend },
        }
    }

    pub fn options(&self) -> &Brotli {
        &self.options
    }

    pub fn update(&mut self, data: &[u8]) -> Result<Vec<u8>, BrotliError> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => Ok(provider.update(*handle, data)?),
        }
    }

    pub fn finalize(self) -> Result<Vec<u8>, BrotliError> {
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

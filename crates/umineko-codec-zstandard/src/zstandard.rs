use alloc::vec::Vec;
use crate::errors::ZstandardError;

use umineko_helpers::provider::{CodecDirection, CodecProvider, CodecProviderRequest, CodecProviders, ProviderBackend};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Zstandard {
    pub level: i8,
    pub window: u8,
        pub limit: Option<usize>,
}

impl Default for Zstandard {
    fn default() -> Self {
        Self {
            level: 3,
            window: 23,
            limit: None,
        }
    }
}

impl Zstandard {
    pub const NAME: &'static str = "zstd";

    pub fn request(&self, direction: CodecDirection) -> CodecProviderRequest<'_> {
        CodecProviderRequest::new(Self::NAME, direction).with_level(self.level as i32).with_window(self.window).with_limit(self.limit)
    }

    pub fn encoder(&self) -> ZstandardEncoder {
        ZstandardEncoder::new(self.clone())
    }

    pub fn decoder(&self) -> ZstandardDecoder {
        ZstandardDecoder::new(self.clone())
    }

    pub fn compress(&self, data: &[u8]) -> Result<Vec<u8>, ZstandardError> {
        match CodecProviders::transform(&self.request(CodecDirection::Encode), data)? {
            Some(output) => Ok(output),
            None => todo!(),
        }
    }

    pub fn decompress(&self, data: &[u8]) -> Result<Vec<u8>, ZstandardError> {
        match CodecProviders::transform(&self.request(CodecDirection::Decode), data)? {
            Some(output) => Ok(output),
            None => todo!(),
        }
    }
}

#[derive(Debug)]
pub struct ZstandardEncoder {
    options: Zstandard,
    backend: ProviderBackend<dyn CodecProvider>,
}

impl ZstandardEncoder {
    pub fn new(options: Zstandard) -> Self {
        match CodecProviders::backend(&options.request(CodecDirection::Encode)) {
            ProviderBackend::Builtin => todo!(),
            backend => Self { options, backend },
        }
    }

    pub fn options(&self) -> &Zstandard {
        &self.options
    }

    pub fn update(&mut self, data: &[u8]) -> Result<Vec<u8>, ZstandardError> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => Ok(provider.update(*handle, data)?),
        }
    }

    pub fn finalize(self) -> Result<Vec<u8>, ZstandardError> {
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
pub struct ZstandardDecoder {
    options: Zstandard,
    backend: ProviderBackend<dyn CodecProvider>,
}

impl ZstandardDecoder {
    pub fn new(options: Zstandard) -> Self {
        match CodecProviders::backend(&options.request(CodecDirection::Decode)) {
            ProviderBackend::Builtin => todo!(),
            backend => Self { options, backend },
        }
    }

    pub fn options(&self) -> &Zstandard {
        &self.options
    }

    pub fn update(&mut self, data: &[u8]) -> Result<Vec<u8>, ZstandardError> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => Ok(provider.update(*handle, data)?),
        }
    }

    pub fn finalize(self) -> Result<Vec<u8>, ZstandardError> {
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

use alloc::vec::Vec;
use crate::errors::LZMAError;

use umineko_helpers::provider::{CodecDirection, CodecProvider, CodecProviderRequest, CodecProviders, ProviderBackend};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LZMAProperties {
    pub literal_context: u8,
    pub literal_position: u8,
    pub position: u8,
    pub dictionary: u32,
}

impl Default for LZMAProperties {
    fn default() -> Self {
        Self { literal_context: 3, literal_position: 0, position: 2, dictionary: 8 * 1024 * 1024 }
    }
}

impl LZMAProperties {
    pub fn encode(&self) -> [u8; 5] {
        todo!()
    }

    pub fn decode(data: &[u8; 5]) -> Result<Self, LZMAError> {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LZMA {
    pub level: u8,
    pub properties: LZMAProperties,
        pub limit: Option<usize>,
}

impl Default for LZMA {
    fn default() -> Self {
        Self {
            level: 6,
            properties: LZMAProperties::default(),
            limit: None,
        }
    }
}

impl LZMA {
    pub const NAME: &'static str = "lzma";

    pub fn request(&self, direction: CodecDirection) -> CodecProviderRequest<'_> {
        CodecProviderRequest::new(Self::NAME, direction).with_level(self.level as i32).with_limit(self.limit)
    }

    pub fn encoder(&self) -> LZMAEncoder {
        LZMAEncoder::new(self.clone())
    }

    pub fn decoder(&self) -> LZMADecoder {
        LZMADecoder::new(self.clone())
    }

    pub fn compress(&self, data: &[u8]) -> Result<Vec<u8>, LZMAError> {
        match CodecProviders::transform(&self.request(CodecDirection::Encode), data)? {
            Some(output) => Ok(output),
            None => todo!(),
        }
    }

    pub fn decompress(&self, data: &[u8]) -> Result<Vec<u8>, LZMAError> {
        match CodecProviders::transform(&self.request(CodecDirection::Decode), data)? {
            Some(output) => Ok(output),
            None => todo!(),
        }
    }
}

#[derive(Debug)]
pub struct LZMAEncoder {
    options: LZMA,
    backend: ProviderBackend<dyn CodecProvider>,
}

impl LZMAEncoder {
    pub fn new(options: LZMA) -> Self {
        match CodecProviders::backend(&options.request(CodecDirection::Encode)) {
            ProviderBackend::Builtin => todo!(),
            backend => Self { options, backend },
        }
    }

    pub fn options(&self) -> &LZMA {
        &self.options
    }

    pub fn update(&mut self, data: &[u8]) -> Result<Vec<u8>, LZMAError> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => Ok(provider.update(*handle, data)?),
        }
    }

    pub fn finalize(self) -> Result<Vec<u8>, LZMAError> {
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
pub struct LZMADecoder {
    options: LZMA,
    backend: ProviderBackend<dyn CodecProvider>,
}

impl LZMADecoder {
    pub fn new(options: LZMA) -> Self {
        match CodecProviders::backend(&options.request(CodecDirection::Decode)) {
            ProviderBackend::Builtin => todo!(),
            backend => Self { options, backend },
        }
    }

    pub fn options(&self) -> &LZMA {
        &self.options
    }

    pub fn update(&mut self, data: &[u8]) -> Result<Vec<u8>, LZMAError> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => Ok(provider.update(*handle, data)?),
        }
    }

    pub fn finalize(self) -> Result<Vec<u8>, LZMAError> {
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

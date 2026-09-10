use alloc::{string::String, vec::Vec};
use crate::errors::GzipError;

use umineko_helpers::provider::{CodecDirection, CodecProvider, CodecProviderRequest, CodecProviders, ProviderBackend};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GzipHeader {
    pub modified: Option<u32>,
    pub name: Option<String>,
    pub comment: Option<String>,
    pub extra: Option<Vec<u8>>,
    pub operating_system: u8,
}

impl Default for GzipHeader {
    fn default() -> Self {
        Self { modified: None, name: None, comment: None, extra: None, operating_system: 255 }
    }
}

impl GzipHeader {
    pub fn encode(&self) -> Vec<u8> {
        todo!()
    }

    pub fn decode(data: &[u8]) -> Result<(Self, usize), GzipError> {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gzip {
    pub level: u8,
    pub header: GzipHeader,
        pub limit: Option<usize>,
}

impl Default for Gzip {
    fn default() -> Self {
        Self {
            level: 6,
            header: GzipHeader::default(),
            limit: None,
        }
    }
}

impl Gzip {
    pub const NAME: &'static str = "gzip";

    pub fn request(&self, direction: CodecDirection) -> CodecProviderRequest<'_> {
        CodecProviderRequest::new(Self::NAME, direction).with_level(self.level as i32).with_limit(self.limit)
    }

    pub fn encoder(&self) -> GzipEncoder {
        GzipEncoder::new(self.clone())
    }

    pub fn decoder(&self) -> GzipDecoder {
        GzipDecoder::new(self.clone())
    }

    pub fn compress(&self, data: &[u8]) -> Result<Vec<u8>, GzipError> {
        match CodecProviders::transform(&self.request(CodecDirection::Encode), data)? {
            Some(output) => Ok(output),
            None => todo!(),
        }
    }

    pub fn decompress(&self, data: &[u8]) -> Result<Vec<u8>, GzipError> {
        match CodecProviders::transform(&self.request(CodecDirection::Decode), data)? {
            Some(output) => Ok(output),
            None => todo!(),
        }
    }
}

#[derive(Debug)]
pub struct GzipEncoder {
    options: Gzip,
    backend: ProviderBackend<dyn CodecProvider>,
}

impl GzipEncoder {
    pub fn new(options: Gzip) -> Self {
        match CodecProviders::backend(&options.request(CodecDirection::Encode)) {
            ProviderBackend::Builtin => todo!(),
            backend => Self { options, backend },
        }
    }

    pub fn options(&self) -> &Gzip {
        &self.options
    }

    pub fn update(&mut self, data: &[u8]) -> Result<Vec<u8>, GzipError> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => Ok(provider.update(*handle, data)?),
        }
    }

    pub fn finalize(self) -> Result<Vec<u8>, GzipError> {
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
pub struct GzipDecoder {
    options: Gzip,
    backend: ProviderBackend<dyn CodecProvider>,
}

impl GzipDecoder {
    pub fn new(options: Gzip) -> Self {
        match CodecProviders::backend(&options.request(CodecDirection::Decode)) {
            ProviderBackend::Builtin => todo!(),
            backend => Self { options, backend },
        }
    }

    pub fn options(&self) -> &Gzip {
        &self.options
    }

    pub fn update(&mut self, data: &[u8]) -> Result<Vec<u8>, GzipError> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => Ok(provider.update(*handle, data)?),
        }
    }

    pub fn finalize(self) -> Result<Vec<u8>, GzipError> {
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

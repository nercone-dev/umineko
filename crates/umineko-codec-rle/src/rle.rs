use alloc::vec::Vec;
use crate::errors::RLEError;

use umineko_helpers::provider::{CodecDirection, CodecProvider, CodecProviderRequest, CodecProviders, ProviderBackend};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RLE {
    pub minimum_run: usize,
        pub limit: Option<usize>,
}

impl Default for RLE {
    fn default() -> Self {
        Self {
            minimum_run: 3,
            limit: None,
        }
    }
}

impl RLE {
    pub const NAME: &'static str = "rle";
    /// The longest run one token repeats, as PackBits counts it.
    pub const MAXIMUM_RUN: usize = 128;
    /// The longest literal stretch one token copies.
    pub const MAXIMUM_LITERAL: usize = 128;
    /// The token PackBits reserves and every decoder skips.
    pub const NOOP: u8 = 128;

    /// The shortest run this codec turns into a token, which is never below two.
    pub fn run(&self) -> usize {
        self.minimum_run.max(2)
    }

    /// Encodes `data` as PackBits tokens, which is what the builtin codec writes.
    pub fn encode(&self, data: &[u8]) -> Result<Vec<u8>, RLEError> {
        let mut output = Vec::new();
        let mut offset = 0;
        while offset < data.len() {
            let run = Self::repeat(data, offset).min(Self::MAXIMUM_RUN);
            if run >= self.run() {
                output.push((257 - run) as u8);
                output.push(data[offset]);
                offset += run;
                continue;
            }
            let start = offset;
            while offset < data.len() && offset - start < Self::MAXIMUM_LITERAL {
                let run = Self::repeat(data, offset);
                if run >= self.run() {
                    break;
                }
                offset += run;
            }
            offset = start + (offset - start).min(Self::MAXIMUM_LITERAL);
            output.push((offset - start - 1) as u8);
            output.extend_from_slice(&data[start..offset]);
        }
        Ok(output)
    }

    /// Decodes PackBits tokens, which is what the builtin codec reads.
    pub fn decode(&self, data: &[u8]) -> Result<Vec<u8>, RLEError> {
        let mut output = Vec::new();
        let mut offset = 0;
        while offset < data.len() {
            let token = data[offset];
            offset += 1;
            let (start, length) = match token {
                Self::NOOP => continue,
                token if token < Self::NOOP => (offset, token as usize + 1),
                token => (offset, 257 - token as usize),
            };
            let repeated = token > Self::NOOP;
            let taken = match repeated {
                true => 1,
                false => length,
            };
            if start + taken > data.len() {
                return Err(RLEError::Truncated);
            }
            if self.limit.is_some_and(|limit| output.len() + length > limit) {
                return Err(RLEError::Limit);
            }
            match repeated {
                true => output.resize(output.len() + length, data[start]),
                false => output.extend_from_slice(&data[start..start + length]),
            }
            offset += taken;
        }
        Ok(output)
    }

    /// The length of the run of equal bytes starting at `offset`.
    pub fn repeat(data: &[u8], offset: usize) -> usize {
        data[offset..].iter().take_while(|byte| **byte == data[offset]).count()
    }

    pub fn request(&self, direction: CodecDirection) -> CodecProviderRequest<'_> {
        CodecProviderRequest::new(Self::NAME, direction).with_limit(self.limit)
    }

    pub fn encoder(&self) -> RLEEncoder {
        RLEEncoder::new(self.clone())
    }

    pub fn decoder(&self) -> RLEDecoder {
        RLEDecoder::new(self.clone())
    }

    pub fn compress(&self, data: &[u8]) -> Result<Vec<u8>, RLEError> {
        match CodecProviders::transform(&self.request(CodecDirection::Encode), data)? {
            Some(output) => Ok(output),
            None => self.encode(data),
        }
    }

    pub fn decompress(&self, data: &[u8]) -> Result<Vec<u8>, RLEError> {
        match CodecProviders::transform(&self.request(CodecDirection::Decode), data)? {
            Some(output) => Ok(output),
            None => self.decode(data),
        }
    }
}

#[derive(Debug)]
pub struct RLEEncoder {
    options: RLE,
    input: Vec<u8>,
    backend: ProviderBackend<dyn CodecProvider>,
}

impl RLEEncoder {
    pub fn new(options: RLE) -> Self {
        match CodecProviders::backend(&options.request(CodecDirection::Encode)) {
            ProviderBackend::Builtin => Self { options, input: Vec::new(), backend: ProviderBackend::Builtin },
            backend => Self { options, input: Vec::new(), backend },
        }
    }

    pub fn options(&self) -> &RLE {
        &self.options
    }

    /// Holds `data` until the stream is finalized, which is when the builtin codec runs.
    pub fn update(&mut self, data: &[u8]) -> Result<Vec<u8>, RLEError> {
        match &self.backend {
            ProviderBackend::Builtin => {
                self.input.extend_from_slice(data);
                Ok(Vec::new())
            }
            ProviderBackend::Handle { provider, handle } => Ok(provider.update(*handle, data)?),
        }
    }

    pub fn finalize(self) -> Result<Vec<u8>, RLEError> {
        match &self.backend {
            ProviderBackend::Builtin => self.options.encode(&self.input),
            ProviderBackend::Handle { provider, handle } => Ok(provider.finalize(*handle)?),
        }
    }

    pub fn reset(&mut self) {
        match &self.backend {
            ProviderBackend::Builtin => self.input.clear(),
            ProviderBackend::Handle { provider, handle } => provider.reset(*handle),
        }
    }
}

#[derive(Debug)]
pub struct RLEDecoder {
    options: RLE,
    input: Vec<u8>,
    backend: ProviderBackend<dyn CodecProvider>,
}

impl RLEDecoder {
    pub fn new(options: RLE) -> Self {
        match CodecProviders::backend(&options.request(CodecDirection::Decode)) {
            ProviderBackend::Builtin => Self { options, input: Vec::new(), backend: ProviderBackend::Builtin },
            backend => Self { options, input: Vec::new(), backend },
        }
    }

    pub fn options(&self) -> &RLE {
        &self.options
    }

    /// Holds `data` until the stream is finalized, which is when the builtin codec runs.
    pub fn update(&mut self, data: &[u8]) -> Result<Vec<u8>, RLEError> {
        match &self.backend {
            ProviderBackend::Builtin => {
                self.input.extend_from_slice(data);
                Ok(Vec::new())
            }
            ProviderBackend::Handle { provider, handle } => Ok(provider.update(*handle, data)?),
        }
    }

    pub fn finalize(self) -> Result<Vec<u8>, RLEError> {
        match &self.backend {
            ProviderBackend::Builtin => self.options.decode(&self.input),
            ProviderBackend::Handle { provider, handle } => Ok(provider.finalize(*handle)?),
        }
    }

    pub fn reset(&mut self) {
        match &self.backend {
            ProviderBackend::Builtin => self.input.clear(),
            ProviderBackend::Handle { provider, handle } => provider.reset(*handle),
        }
    }
}

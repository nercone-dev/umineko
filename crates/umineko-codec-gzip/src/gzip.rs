use alloc::{string::String, vec::Vec};
use crate::errors::GzipError;

use umineko_codec_deflate::Deflate;
use umineko_hash_crc::{CRC32, CRC32Parameters};

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
    pub const MAGIC: [u8; 2] = [0x1F, 0x8B];
    /// The only compression method the format defines.
    pub const DEFLATE: u8 = 8;
    /// The smallest header, which carries no optional field.
    pub const SIZE: usize = 10;
    pub const TEXT: u8 = 1;
    pub const CHECKSUM: u8 = 2;
    pub const EXTRA: u8 = 4;
    pub const NAME: u8 = 8;
    pub const COMMENT: u8 = 16;
    /// The operating system byte that stands for an unknown system.
    pub const UNKNOWN: u8 = 255;

    /// The flags this header carries.
    pub fn flags(&self) -> u8 {
        let mut flags = 0;
        if self.extra.is_some() {
            flags |= Self::EXTRA;
        }
        if self.name.is_some() {
            flags |= Self::NAME;
        }
        if self.comment.is_some() {
            flags |= Self::COMMENT;
        }
        flags
    }

    /// The bytes a text carries, one per character, as the format asks.
    pub fn latin1(text: &str) -> Vec<u8> {
        text.chars().map(|character| u8::try_from(character as u32).unwrap_or(b'?')).collect()
    }

    /// The text a run of bytes carries, one character per byte.
    pub fn text(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| *byte as char).collect()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(Self::SIZE);
        output.extend_from_slice(&Self::MAGIC);
        output.push(Self::DEFLATE);
        output.push(self.flags());
        output.extend_from_slice(&self.modified.unwrap_or(0).to_le_bytes());
        output.push(0);
        output.push(self.operating_system);
        if let Some(extra) = &self.extra {
            output.extend_from_slice(&(extra.len() as u16).to_le_bytes());
            output.extend_from_slice(extra);
        }
        if let Some(name) = &self.name {
            output.extend_from_slice(&Self::latin1(name));
            output.push(0);
        }
        if let Some(comment) = &self.comment {
            output.extend_from_slice(&Self::latin1(comment));
            output.push(0);
        }
        output
    }

    pub fn decode(data: &[u8]) -> Result<(Self, usize), GzipError> {
        if data.len() < Self::SIZE {
            return Err(GzipError::Truncated);
        }
        if data[..2] != Self::MAGIC {
            return Err(GzipError::Format);
        }
        if data[2] != Self::DEFLATE {
            return Err(GzipError::Format);
        }
        let flags = data[3];
        let modified = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let mut header = Self { modified: Some(modified).filter(|modified| *modified != 0), name: None, comment: None, extra: None, operating_system: data[9] };
        let mut offset = Self::SIZE;
        if flags & Self::EXTRA != 0 {
            if offset + 2 > data.len() {
                return Err(GzipError::Truncated);
            }
            let length = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2;
            if offset + length > data.len() {
                return Err(GzipError::Truncated);
            }
            header.extra = Some(data[offset..offset + length].to_vec());
            offset += length;
        }
        if flags & Self::NAME != 0 {
            let (text, length) = Self::terminated(&data[offset..])?;
            header.name = Some(text);
            offset += length;
        }
        if flags & Self::COMMENT != 0 {
            let (text, length) = Self::terminated(&data[offset..])?;
            header.comment = Some(text);
            offset += length;
        }
        if flags & Self::CHECKSUM != 0 {
            if offset + 2 > data.len() {
                return Err(GzipError::Truncated);
            }
            let carried = u16::from_le_bytes([data[offset], data[offset + 1]]);
            if carried != CRC32::digest(CRC32Parameters::IEEE, &data[..offset]) as u16 {
                return Err(GzipError::Checksum);
            }
            offset += 2;
        }
        Ok((header, offset))
    }

    /// The text a zero terminated field carries, and the bytes it spends.
    pub fn terminated(data: &[u8]) -> Result<(String, usize), GzipError> {
        let end = data.iter().position(|byte| *byte == 0).ok_or(GzipError::Truncated)?;
        Ok((Self::text(&data[..end]), end + 1))
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
    /// The trailer bytes: the checksum of the content and its length.
    pub const TRAILER: usize = 8;

    /// The extra flags byte, which stands for how hard the encoder worked.
    pub fn effort(&self) -> u8 {
        match self.level {
            9 => 2,
            0 | 1 => 4,
            _ => 0,
        }
    }

    /// The deflate codec this member carries its content under.
    pub fn deflate(&self) -> Deflate {
        Deflate { level: self.level, window: 15, limit: self.limit }
    }

    /// Encodes `data` as one gzip member, which is what the builtin codec writes.
    pub fn encode(&self, data: &[u8]) -> Result<Vec<u8>, GzipError> {
        let mut output = self.header.encode();
        output[8] = self.effort();
        output.extend_from_slice(&self.deflate().encode(data)?);
        output.extend_from_slice(&CRC32::digest(CRC32Parameters::IEEE, data).to_le_bytes());
        output.extend_from_slice(&(data.len() as u32).to_le_bytes());
        Ok(output)
    }

    /// Decodes every gzip member in `data`, which is what the builtin codec reads.
    pub fn decode(&self, data: &[u8]) -> Result<Vec<u8>, GzipError> {
        let mut output = Vec::new();
        let mut offset = 0;
        while offset < data.len() {
            let (_, header) = GzipHeader::decode(&data[offset..])?;
            let start = offset + header;
            let (member, spent) = self.deflate().inflate_stream(&data[start..])?;
            let trailer = start + spent;
            if data.len() < trailer + Self::TRAILER {
                return Err(GzipError::Truncated);
            }
            let carried = &data[trailer..trailer + Self::TRAILER];
            if CRC32::digest(CRC32Parameters::IEEE, &member) != u32::from_le_bytes([carried[0], carried[1], carried[2], carried[3]]) {
                return Err(GzipError::Checksum);
            }
            if member.len() as u32 != u32::from_le_bytes([carried[4], carried[5], carried[6], carried[7]]) {
                return Err(GzipError::Format);
            }
            if self.limit.is_some_and(|limit| output.len() + member.len() > limit) {
                return Err(GzipError::Limit);
            }
            match output.is_empty() {
                true => output = member,
                false => output.extend_from_slice(&member),
            }
            offset = trailer + Self::TRAILER;
        }
        Ok(output)
    }

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
            None => self.encode(data),
        }
    }

    pub fn decompress(&self, data: &[u8]) -> Result<Vec<u8>, GzipError> {
        match CodecProviders::transform(&self.request(CodecDirection::Decode), data)? {
            Some(output) => Ok(output),
            None => self.decode(data),
        }
    }
}

#[derive(Debug)]
pub struct GzipEncoder {
    options: Gzip,
    input: Vec<u8>,
    backend: ProviderBackend<dyn CodecProvider>,
}

impl GzipEncoder {
    pub fn new(options: Gzip) -> Self {
        match CodecProviders::backend(&options.request(CodecDirection::Encode)) {
            ProviderBackend::Builtin => Self { options, input: Vec::new(), backend: ProviderBackend::Builtin },
            backend => Self { options, input: Vec::new(), backend },
        }
    }

    pub fn options(&self) -> &Gzip {
        &self.options
    }

    /// Holds `data` until the stream is finalized, which is when the builtin codec runs.
    pub fn update(&mut self, data: &[u8]) -> Result<Vec<u8>, GzipError> {
        match &self.backend {
            ProviderBackend::Builtin => {
                self.input.extend_from_slice(data);
                Ok(Vec::new())
            }
            ProviderBackend::Handle { provider, handle } => Ok(provider.update(*handle, data)?),
        }
    }

    pub fn finalize(self) -> Result<Vec<u8>, GzipError> {
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
pub struct GzipDecoder {
    options: Gzip,
    input: Vec<u8>,
    backend: ProviderBackend<dyn CodecProvider>,
}

impl GzipDecoder {
    pub fn new(options: Gzip) -> Self {
        match CodecProviders::backend(&options.request(CodecDirection::Decode)) {
            ProviderBackend::Builtin => Self { options, input: Vec::new(), backend: ProviderBackend::Builtin },
            backend => Self { options, input: Vec::new(), backend },
        }
    }

    pub fn options(&self) -> &Gzip {
        &self.options
    }

    /// Holds `data` until the stream is finalized, which is when the builtin codec runs.
    pub fn update(&mut self, data: &[u8]) -> Result<Vec<u8>, GzipError> {
        match &self.backend {
            ProviderBackend::Builtin => {
                self.input.extend_from_slice(data);
                Ok(Vec::new())
            }
            ProviderBackend::Handle { provider, handle } => Ok(provider.update(*handle, data)?),
        }
    }

    pub fn finalize(self) -> Result<Vec<u8>, GzipError> {
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

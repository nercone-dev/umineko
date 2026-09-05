use alloc::vec;
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

/// Finds the longest earlier copy of the bytes at a position, through a chain of hash buckets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LZ4Matcher {
    window: usize,
    probes: usize,
    head: Vec<u32>,
    chain: Vec<u32>,
}

impl LZ4Matcher {
    pub const HASH_BITS: u32 = 16;
    pub const HASH_SIZE: usize = 1 << Self::HASH_BITS;
    /// The shortest run of bytes a match may cover.
    pub const MINIMUM: usize = 4;
    /// The widest distance the two byte offset carries.
    pub const WINDOW: usize = 65535;

    /// The fewest buckets a search spreads its positions over.
    pub const MINIMUM_HASH_SIZE: usize = 256;

    /// A matcher whose tables hold whichever is shorter: one window, or the whole of `length` bytes.
    pub fn new(probes: usize, length: usize) -> Self {
        let window = Self::WINDOW.min(length.max(1));
        let buckets = window.next_power_of_two().clamp(Self::MINIMUM_HASH_SIZE, Self::HASH_SIZE);
        Self { window, probes: probes.max(1), head: vec![0; buckets], chain: vec![0; window.next_power_of_two()] }
    }

    /// The number of buckets positions spread over, which the window sets.
    pub fn buckets(&self) -> usize {
        self.head.len()
    }

    /// The bucket the four bytes at `offset` fall into.
    pub fn hash(&self, data: &[u8], offset: usize) -> usize {
        match offset + Self::MINIMUM <= data.len() {
            true => (u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]).wrapping_mul(2654435761) >> (32 - Self::HASH_BITS)) as usize & (self.head.len() - 1),
            false => 0,
        }
    }

    /// The chain slot one position keeps its predecessor in, which wraps every window.
    pub fn slot(&self, offset: usize) -> usize {
        offset & (self.chain.len() - 1)
    }

    pub fn insert(&mut self, data: &[u8], offset: usize) {
        if offset + Self::MINIMUM <= data.len() {
            let (bucket, slot) = (self.hash(data, offset), self.slot(offset));
            self.chain[slot] = self.head[bucket];
            self.head[bucket] = offset as u32 + 1;
        }
    }

    /// The number of leading bytes two stretches share, compared a word at a time.
    pub fn common(left: &[u8], right: &[u8]) -> usize {
        let shared = left.len().min(right.len());
        let mut matched = 0;
        while matched + 8 <= shared {
            let difference = u64::from_le_bytes(left[matched..matched + 8].try_into().unwrap_or_default()) ^ u64::from_le_bytes(right[matched..matched + 8].try_into().unwrap_or_default());
            if difference != 0 {
                return matched + (difference.trailing_zeros() / 8) as usize;
            }
            matched += 8;
        }
        matched + left[matched..shared].iter().zip(&right[matched..shared]).take_while(|(left, right)| left == right).count()
    }

    /// The distance and length of the longest match at `offset`, bounded by `limit` bytes.
    pub fn find(&self, data: &[u8], offset: usize, limit: usize) -> Option<(usize, usize)> {
        let available = limit.min(data.len() - offset);
        if available < Self::MINIMUM {
            return None;
        }
        let earliest = offset.saturating_sub(self.window);
        let target = &data[offset..offset + available];
        let mut candidate = self.head[self.hash(data, offset)] as usize;
        let mut best = (0, 0);
        for _ in 0..self.probes {
            if candidate == 0 {
                break;
            }
            let position = candidate - 1;
            if position < earliest || position >= offset {
                break;
            }
            if best.1 == 0 || data[position + best.1] == target[best.1] {
                let length = Self::common(&data[position..], target);
                if length > best.1 {
                    best = (offset - position, length);
                    if length == available {
                        break;
                    }
                }
            }
            candidate = self.chain[self.slot(position)] as usize;
        }
        match best.1 >= Self::MINIMUM {
            true => Some(best),
            false => None,
        }
    }
}

impl LZ4 {
    pub const NAME: &'static str = "lz4";
    /// The distance from the end of a block within which no match may start.
    pub const MATCH_LIMIT: usize = 12;
    /// The number of bytes at the end of a block that are always literals.
    pub const LAST_LITERALS: usize = 5;
    /// The nibble value that says a length carries on in the bytes that follow.
    pub const EXTENDED: usize = 15;
    /// The shortest run of bytes a match may cover.
    pub const MINIMUM_MATCH: usize = 4;

    /// The number of earlier positions one search walks, which the level sets.
    pub fn probes(&self) -> usize {
        (self.level.max(1) as usize) * 64
    }

    /// Writes a length that overflows its nibble as a run of bytes.
    pub fn extend(output: &mut Vec<u8>, length: usize) {
        let mut left = length - Self::EXTENDED;
        while left >= 255 {
            output.push(255);
            left -= 255;
        }
        output.push(left as u8);
    }

    /// Reads a length that overflowed its nibble out of the bytes that follow.
    pub fn extended(data: &[u8], offset: &mut usize) -> Result<usize, LZ4Error> {
        let mut length = Self::EXTENDED;
        loop {
            let byte = *data.get(*offset).ok_or(LZ4Error::Truncated)?;
            *offset += 1;
            length += byte as usize;
            if byte != 255 {
                return Ok(length);
            }
        }
    }

    /// Writes one sequence: a run of literals and the match that follows it.
    pub fn sequence(output: &mut Vec<u8>, literals: &[u8], distance: usize, length: usize) {
        let literal = literals.len().min(Self::EXTENDED);
        let matched = length.saturating_sub(Self::MINIMUM_MATCH).min(Self::EXTENDED);
        output.push(((literal << 4) | matched) as u8);
        if literals.len() >= Self::EXTENDED {
            Self::extend(output, literals.len());
        }
        output.extend_from_slice(literals);
        if length != 0 {
            output.extend_from_slice(&(distance as u16).to_le_bytes());
            if length - Self::MINIMUM_MATCH >= Self::EXTENDED {
                Self::extend(output, length - Self::MINIMUM_MATCH);
            }
        }
    }

    /// Encodes `data` as an LZ4 block, which is what the builtin codec writes.
    pub fn encode(&self, data: &[u8]) -> Result<Vec<u8>, LZ4Error> {
        let mut matcher = LZ4Matcher::new(self.probes(), data.len());
        let mut output = Vec::new();
        let (mut anchor, mut offset) = (0, 0);
        let matches = data.len().saturating_sub(Self::MATCH_LIMIT);
        let literals = data.len().saturating_sub(Self::LAST_LITERALS);
        while offset < matches {
            match matcher.find(data, offset, literals - offset) {
                Some((distance, length)) => {
                    Self::sequence(&mut output, &data[anchor..offset], distance, length);
                    for step in 0..length {
                        matcher.insert(data, offset + step);
                    }
                    offset += length;
                    anchor = offset;
                }
                None => {
                    matcher.insert(data, offset);
                    offset += 1;
                }
            }
        }
        Self::sequence(&mut output, &data[anchor..], 0, 0);
        Ok(output)
    }

    /// Decodes an LZ4 block, which is what the builtin codec reads.
    pub fn decode(&self, data: &[u8]) -> Result<Vec<u8>, LZ4Error> {
        let mut output = Vec::new();
        let mut offset = 0;
        while offset < data.len() {
            let token = data[offset] as usize;
            offset += 1;
            let mut literal = token >> 4;
            if literal == Self::EXTENDED {
                literal = Self::extended(data, &mut offset)?;
            }
            if offset + literal > data.len() {
                return Err(LZ4Error::Truncated);
            }
            if self.limit.is_some_and(|limit| output.len() + literal > limit) {
                return Err(LZ4Error::Limit);
            }
            output.extend_from_slice(&data[offset..offset + literal]);
            offset += literal;
            if offset == data.len() {
                return Ok(output);
            }
            if offset + 2 > data.len() {
                return Err(LZ4Error::Truncated);
            }
            let distance = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2;
            let mut length = token & Self::EXTENDED;
            if length == Self::EXTENDED {
                length = Self::extended(data, &mut offset)?;
            }
            length += Self::MINIMUM_MATCH;
            if distance == 0 || distance > output.len() {
                return Err(LZ4Error::Format);
            }
            if self.limit.is_some_and(|limit| output.len() + length > limit) {
                return Err(LZ4Error::Limit);
            }
            let start = output.len() - distance;
            for step in 0..length {
                output.push(output[start + step]);
            }
        }
        Ok(output)
    }

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
            None => self.encode(data),
        }
    }

    pub fn decompress(&self, data: &[u8]) -> Result<Vec<u8>, LZ4Error> {
        match CodecProviders::transform(&self.request(CodecDirection::Decode), data)? {
            Some(output) => Ok(output),
            None => self.decode(data),
        }
    }
}

#[derive(Debug)]
pub struct LZ4Encoder {
    options: LZ4,
    input: Vec<u8>,
    backend: ProviderBackend<dyn CodecProvider>,
}

impl LZ4Encoder {
    pub fn new(options: LZ4) -> Self {
        match CodecProviders::backend(&options.request(CodecDirection::Encode)) {
            ProviderBackend::Builtin => Self { options, input: Vec::new(), backend: ProviderBackend::Builtin },
            backend => Self { options, input: Vec::new(), backend },
        }
    }

    pub fn options(&self) -> &LZ4 {
        &self.options
    }

    /// Holds `data` until the stream is finalized, which is when the builtin codec runs.
    pub fn update(&mut self, data: &[u8]) -> Result<Vec<u8>, LZ4Error> {
        match &self.backend {
            ProviderBackend::Builtin => {
                self.input.extend_from_slice(data);
                Ok(Vec::new())
            }
            ProviderBackend::Handle { provider, handle } => Ok(provider.update(*handle, data)?),
        }
    }

    pub fn finalize(self) -> Result<Vec<u8>, LZ4Error> {
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
pub struct LZ4Decoder {
    options: LZ4,
    input: Vec<u8>,
    backend: ProviderBackend<dyn CodecProvider>,
}

impl LZ4Decoder {
    pub fn new(options: LZ4) -> Self {
        match CodecProviders::backend(&options.request(CodecDirection::Decode)) {
            ProviderBackend::Builtin => Self { options, input: Vec::new(), backend: ProviderBackend::Builtin },
            backend => Self { options, input: Vec::new(), backend },
        }
    }

    pub fn options(&self) -> &LZ4 {
        &self.options
    }

    /// Holds `data` until the stream is finalized, which is when the builtin codec runs.
    pub fn update(&mut self, data: &[u8]) -> Result<Vec<u8>, LZ4Error> {
        match &self.backend {
            ProviderBackend::Builtin => {
                self.input.extend_from_slice(data);
                Ok(Vec::new())
            }
            ProviderBackend::Handle { provider, handle } => Ok(provider.update(*handle, data)?),
        }
    }

    pub fn finalize(self) -> Result<Vec<u8>, LZ4Error> {
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

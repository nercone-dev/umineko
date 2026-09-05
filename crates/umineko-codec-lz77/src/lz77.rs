use alloc::vec;
use alloc::vec::Vec;
use crate::errors::LZ77Error;

use umineko_helpers::provider::{CodecDirection, CodecProvider, CodecProviderRequest, CodecProviders, ProviderBackend};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LZ77 {
    pub window: usize,
    pub lookahead: usize,
        pub limit: Option<usize>,
}

impl Default for LZ77 {
    fn default() -> Self {
        Self {
            window: 32 * 1024,
            lookahead: 258,
            limit: None,
        }
    }
}

/// Finds the longest earlier copy of the bytes at a position, through a chain of hash buckets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LZ77Matcher {
    window: usize,
    lookahead: usize,
    probes: usize,
    head: Vec<u32>,
    chain: Vec<u32>,
}

impl LZ77Matcher {
    pub const HASH_BITS: u32 = 15;
    pub const HASH_SIZE: usize = 1 << Self::HASH_BITS;
    /// The fewest buckets a search spreads its positions over.
    pub const MINIMUM_HASH_SIZE: usize = 256;
    /// The shortest run of bytes a match may cover.
    pub const MINIMUM: usize = 3;
    /// The number of earlier positions one search walks before it settles.
    pub const PROBES: usize = 128;

    /// A matcher whose tables hold whichever is shorter: one window, or the whole of `length` bytes.
    pub fn new(window: usize, lookahead: usize, length: usize) -> Self {
        let window = window.clamp(1, length.max(1));
        let buckets = window.next_power_of_two().clamp(Self::MINIMUM_HASH_SIZE, Self::HASH_SIZE);
        Self { window, lookahead: lookahead.max(Self::MINIMUM), probes: Self::PROBES, head: vec![0; buckets], chain: vec![0; window.next_power_of_two()] }
    }

    pub fn with_probes(self, probes: usize) -> Self {
        Self { probes, ..self }
    }

    /// The number of buckets positions spread over, which the window sets.
    pub fn buckets(&self) -> usize {
        self.head.len()
    }

    /// The bucket the three bytes at `offset` fall into.
    pub fn hash(&self, data: &[u8], offset: usize) -> usize {
        match offset + Self::MINIMUM <= data.len() {
            true => ((data[offset] as usize) << 10 ^ (data[offset + 1] as usize) << 5 ^ data[offset + 2] as usize) & (self.head.len() - 1),
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

    /// The distance and length of the longest match at `offset`, if one reaches `minimum`.
    pub fn find(&self, data: &[u8], offset: usize, minimum: usize, limit: usize) -> Option<(usize, usize)> {
        let available = (data.len() - offset).min(self.lookahead).min(limit);
        let minimum = minimum.max(Self::MINIMUM);
        if available < minimum {
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
        match best.1 >= minimum {
            true => Some(best),
            false => None,
        }
    }
}

impl LZ77 {
    pub const NAME: &'static str = "lz77";
    /// The bytes one token spends: a distance, a length and the byte that follows them.
    pub const TOKEN: usize = 5;

    pub fn matcher(&self, length: usize) -> LZ77Matcher {
        LZ77Matcher::new(self.window.min(u16::MAX as usize), self.lookahead.min(u16::MAX as usize), length)
    }

    /// Encodes `data` as distance, length and literal triples, which is what the builtin codec writes.
    pub fn encode(&self, data: &[u8]) -> Result<Vec<u8>, LZ77Error> {
        let mut matcher = self.matcher(data.len());
        let mut output = Vec::with_capacity(data.len() / 2 + Self::TOKEN);
        let mut offset = 0;
        while offset < data.len() {
            let reserved = data.len() - offset - 1;
            let found = matcher.find(data, offset, LZ77Matcher::MINIMUM, reserved);
            let (distance, length) = found.unwrap_or((0, 0));
            output.extend_from_slice(&(distance as u16).to_le_bytes());
            output.extend_from_slice(&(length as u16).to_le_bytes());
            output.push(data[offset + length]);
            for step in 0..=length {
                matcher.insert(data, offset + step);
            }
            offset += length + 1;
        }
        Ok(output)
    }

    /// Decodes distance, length and literal triples, which is what the builtin codec reads.
    pub fn decode(&self, data: &[u8]) -> Result<Vec<u8>, LZ77Error> {
        let mut output = Vec::with_capacity(data.len());
        for token in data.chunks(Self::TOKEN) {
            if token.len() < Self::TOKEN {
                return Err(LZ77Error::Truncated);
            }
            let distance = u16::from_le_bytes([token[0], token[1]]) as usize;
            let length = u16::from_le_bytes([token[2], token[3]]) as usize;
            if distance > output.len() || (distance == 0 && length != 0) {
                return Err(LZ77Error::Format);
            }
            if self.limit.is_some_and(|limit| output.len() + length + 1 > limit) {
                return Err(LZ77Error::Limit);
            }
            let start = output.len() - distance;
            match distance >= length {
                true => output.extend_from_within(start..start + length),
                false => {
                    output.reserve(length + 1);
                    for step in 0..length {
                        output.push(output[start + step]);
                    }
                }
            }
            output.push(token[4]);
        }
        Ok(output)
    }

    pub fn request(&self, direction: CodecDirection) -> CodecProviderRequest<'_> {
        CodecProviderRequest::new(Self::NAME, direction).with_limit(self.limit)
    }

    pub fn encoder(&self) -> LZ77Encoder {
        LZ77Encoder::new(self.clone())
    }

    pub fn decoder(&self) -> LZ77Decoder {
        LZ77Decoder::new(self.clone())
    }

    pub fn compress(&self, data: &[u8]) -> Result<Vec<u8>, LZ77Error> {
        match CodecProviders::transform(&self.request(CodecDirection::Encode), data)? {
            Some(output) => Ok(output),
            None => self.encode(data),
        }
    }

    pub fn decompress(&self, data: &[u8]) -> Result<Vec<u8>, LZ77Error> {
        match CodecProviders::transform(&self.request(CodecDirection::Decode), data)? {
            Some(output) => Ok(output),
            None => self.decode(data),
        }
    }
}

#[derive(Debug)]
pub struct LZ77Encoder {
    options: LZ77,
    input: Vec<u8>,
    backend: ProviderBackend<dyn CodecProvider>,
}

impl LZ77Encoder {
    pub fn new(options: LZ77) -> Self {
        match CodecProviders::backend(&options.request(CodecDirection::Encode)) {
            ProviderBackend::Builtin => Self { options, input: Vec::new(), backend: ProviderBackend::Builtin },
            backend => Self { options, input: Vec::new(), backend },
        }
    }

    pub fn options(&self) -> &LZ77 {
        &self.options
    }

    /// Holds `data` until the stream is finalized, which is when the builtin codec runs.
    pub fn update(&mut self, data: &[u8]) -> Result<Vec<u8>, LZ77Error> {
        match &self.backend {
            ProviderBackend::Builtin => {
                self.input.extend_from_slice(data);
                Ok(Vec::new())
            }
            ProviderBackend::Handle { provider, handle } => Ok(provider.update(*handle, data)?),
        }
    }

    pub fn finalize(self) -> Result<Vec<u8>, LZ77Error> {
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
pub struct LZ77Decoder {
    options: LZ77,
    input: Vec<u8>,
    backend: ProviderBackend<dyn CodecProvider>,
}

impl LZ77Decoder {
    pub fn new(options: LZ77) -> Self {
        match CodecProviders::backend(&options.request(CodecDirection::Decode)) {
            ProviderBackend::Builtin => Self { options, input: Vec::new(), backend: ProviderBackend::Builtin },
            backend => Self { options, input: Vec::new(), backend },
        }
    }

    pub fn options(&self) -> &LZ77 {
        &self.options
    }

    /// Holds `data` until the stream is finalized, which is when the builtin codec runs.
    pub fn update(&mut self, data: &[u8]) -> Result<Vec<u8>, LZ77Error> {
        match &self.backend {
            ProviderBackend::Builtin => {
                self.input.extend_from_slice(data);
                Ok(Vec::new())
            }
            ProviderBackend::Handle { provider, handle } => Ok(provider.update(*handle, data)?),
        }
    }

    pub fn finalize(self) -> Result<Vec<u8>, LZ77Error> {
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

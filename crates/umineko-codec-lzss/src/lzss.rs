use alloc::vec;
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

/// Finds the longest earlier copy of the bytes at a position, through a chain of hash buckets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LZSSMatcher {
    window: usize,
    lookahead: usize,
    head: Vec<u32>,
    chain: Vec<u32>,
}

impl LZSSMatcher {
    pub const HASH_BITS: u32 = 13;
    pub const HASH_SIZE: usize = 1 << Self::HASH_BITS;
    pub const MINIMUM: usize = 2;

    /// The fewest buckets a search spreads its positions over.
    pub const MINIMUM_HASH_SIZE: usize = 256;

    /// A matcher whose tables hold whichever is shorter: one window, or the whole of `length` bytes.
    pub fn new(window: usize, lookahead: usize, length: usize) -> Self {
        let window = window.clamp(1, length.max(1));
        let buckets = window.next_power_of_two().clamp(Self::MINIMUM_HASH_SIZE, Self::HASH_SIZE);
        Self { window, lookahead: lookahead.max(Self::MINIMUM), head: vec![0; buckets], chain: vec![0; window.next_power_of_two()] }
    }

    /// The number of buckets positions spread over, which the window sets.
    pub fn buckets(&self) -> usize {
        self.head.len()
    }

    /// The bucket the two bytes at `offset` fall into.
    pub fn hash(&self, data: &[u8], offset: usize) -> usize {
        match offset + Self::MINIMUM <= data.len() {
            true => ((data[offset] as usize) << 5 ^ data[offset + 1] as usize) & (self.head.len() - 1),
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
    pub fn find(&self, data: &[u8], offset: usize, minimum: usize) -> Option<(usize, usize)> {
        let available = (data.len() - offset).min(self.lookahead);
        if available < minimum {
            return None;
        }
        let earliest = offset.saturating_sub(self.window);
        let target = &data[offset..offset + available];
        let mut candidate = self.head[self.hash(data, offset)] as usize;
        let mut best = (0, 0);
        while candidate != 0 {
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

impl LZSS {
    pub const NAME: &'static str = "lzss";
    /// The widest distance one token carries, which is twelve bits.
    pub const MAXIMUM_WINDOW: usize = 4096;
    /// The number of lengths one token carries, which is four bits.
    pub const LENGTHS: usize = 16;

    /// The shortest match this codec turns into a token.
    pub fn threshold(&self) -> usize {
        self.threshold.max(2)
    }

    /// The longest match one token carries.
    pub fn maximum(&self) -> usize {
        self.lookahead.min(self.threshold() + Self::LENGTHS - 1)
    }

    pub fn matcher(&self, length: usize) -> LZSSMatcher {
        LZSSMatcher::new(self.window.min(Self::MAXIMUM_WINDOW), self.maximum(), length)
    }

    /// Encodes `data` as flagged literals and distance and length pairs, which is what the builtin codec writes.
    pub fn encode(&self, data: &[u8]) -> Result<Vec<u8>, LZSSError> {
        let mut matcher = self.matcher(data.len());
        let mut output = Vec::with_capacity(data.len() / 2 + 1);
        let mut tokens = Vec::with_capacity(16);
        let mut flags = 0u8;
        let mut held = 0;
        let mut offset = 0;
        while offset < data.len() {
            let found = matcher.find(data, offset, self.threshold());
            let length = match found {
                Some((distance, length)) => {
                    tokens.push(((distance - 1) & 0xFF) as u8);
                    tokens.push(((((distance - 1) >> 8) << 4) | (length - self.threshold())) as u8);
                    length
                }
                None => {
                    flags |= 1 << held;
                    tokens.push(data[offset]);
                    1
                }
            };
            for step in 0..length {
                matcher.insert(data, offset + step);
            }
            offset += length;
            held += 1;
            if held == 8 {
                output.push(flags);
                output.append(&mut tokens);
                (flags, held) = (0, 0);
            }
        }
        if held != 0 {
            output.push(flags);
            output.append(&mut tokens);
        }
        Ok(output)
    }

    /// Decodes flagged literals and distance and length pairs, which is what the builtin codec reads.
    pub fn decode(&self, data: &[u8]) -> Result<Vec<u8>, LZSSError> {
        let mut output = Vec::new();
        let mut offset = 0;
        while offset < data.len() {
            let flags = data[offset];
            offset += 1;
            for held in 0..8 {
                if offset >= data.len() {
                    return Ok(output);
                }
                match flags >> held & 1 == 1 {
                    true => {
                        output.push(data[offset]);
                        offset += 1;
                    }
                    false => {
                        if offset + 2 > data.len() {
                            return Err(LZSSError::Truncated);
                        }
                        let distance = (((data[offset + 1] as usize) >> 4) << 8 | data[offset] as usize) + 1;
                        let length = (data[offset + 1] as usize & 0x0F) + self.threshold();
                        offset += 2;
                        if distance > output.len() {
                            return Err(LZSSError::Format);
                        }
                        if self.limit.is_some_and(|limit| output.len() + length > limit) {
                            return Err(LZSSError::Limit);
                        }
                        let start = output.len() - distance;
                        for step in 0..length {
                            output.push(output[start + step]);
                        }
                    }
                }
            }
        }
        Ok(output)
    }

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
            None => self.encode(data),
        }
    }

    pub fn decompress(&self, data: &[u8]) -> Result<Vec<u8>, LZSSError> {
        match CodecProviders::transform(&self.request(CodecDirection::Decode), data)? {
            Some(output) => Ok(output),
            None => self.decode(data),
        }
    }
}

#[derive(Debug)]
pub struct LZSSEncoder {
    options: LZSS,
    input: Vec<u8>,
    backend: ProviderBackend<dyn CodecProvider>,
}

impl LZSSEncoder {
    pub fn new(options: LZSS) -> Self {
        match CodecProviders::backend(&options.request(CodecDirection::Encode)) {
            ProviderBackend::Builtin => Self { options, input: Vec::new(), backend: ProviderBackend::Builtin },
            backend => Self { options, input: Vec::new(), backend },
        }
    }

    pub fn options(&self) -> &LZSS {
        &self.options
    }

    /// Holds `data` until the stream is finalized, which is when the builtin codec runs.
    pub fn update(&mut self, data: &[u8]) -> Result<Vec<u8>, LZSSError> {
        match &self.backend {
            ProviderBackend::Builtin => {
                self.input.extend_from_slice(data);
                Ok(Vec::new())
            }
            ProviderBackend::Handle { provider, handle } => Ok(provider.update(*handle, data)?),
        }
    }

    pub fn finalize(self) -> Result<Vec<u8>, LZSSError> {
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
pub struct LZSSDecoder {
    options: LZSS,
    input: Vec<u8>,
    backend: ProviderBackend<dyn CodecProvider>,
}

impl LZSSDecoder {
    pub fn new(options: LZSS) -> Self {
        match CodecProviders::backend(&options.request(CodecDirection::Decode)) {
            ProviderBackend::Builtin => Self { options, input: Vec::new(), backend: ProviderBackend::Builtin },
            backend => Self { options, input: Vec::new(), backend },
        }
    }

    pub fn options(&self) -> &LZSS {
        &self.options
    }

    /// Holds `data` until the stream is finalized, which is when the builtin codec runs.
    pub fn update(&mut self, data: &[u8]) -> Result<Vec<u8>, LZSSError> {
        match &self.backend {
            ProviderBackend::Builtin => {
                self.input.extend_from_slice(data);
                Ok(Vec::new())
            }
            ProviderBackend::Handle { provider, handle } => Ok(provider.update(*handle, data)?),
        }
    }

    pub fn finalize(self) -> Result<Vec<u8>, LZSSError> {
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

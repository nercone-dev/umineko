use alloc::vec;
use alloc::vec::Vec;
use crate::errors::LZ78Error;

use umineko_helpers::provider::{CodecDirection, CodecProvider, CodecProviderRequest, CodecProviders, ProviderBackend};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LZ78 {
    pub dictionary: usize,
        pub limit: Option<usize>,
}

impl Default for LZ78 {
    fn default() -> Self {
        Self {
            dictionary: 64 * 1024,
            limit: None,
        }
    }
}

/// The phrases an encoder holds, keyed by the phrase they extend and the byte that extends it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LZ78Dictionary {
    slots: Vec<(u32, u8, u32)>,
    count: usize,
}

impl LZ78Dictionary {
    /// The number of slots one phrase is given, which is what holds a lookup short.
    pub const SPREAD: usize = 2;

    pub fn new(phrases: usize) -> Self {
        Self { slots: vec![(0, 0, LZ78::EMPTY); (phrases.max(1) * Self::SPREAD).next_power_of_two()], count: 0 }
    }

    /// The slot one key holds, or the free slot it would take.
    pub fn probe(&self, phrase: u32, byte: u8) -> usize {
        let mask = self.slots.len() - 1;
        let mut index = (phrase.wrapping_mul(2654435761) ^ (byte as u32).wrapping_mul(2246822519)) as usize & mask;
        while self.slots[index].2 != LZ78::EMPTY && (self.slots[index].0, self.slots[index].1) != (phrase, byte) {
            index = (index + 1) & mask;
        }
        index
    }

    pub fn get(&self, phrase: u32, byte: u8) -> Option<u32> {
        match self.slots[self.probe(phrase, byte)].2 {
            LZ78::EMPTY => None,
            index => Some(index),
        }
    }

    pub fn insert(&mut self, phrase: u32, byte: u8, index: u32) {
        let slot = self.probe(phrase, byte);
        if self.slots[slot].2 == LZ78::EMPTY {
            self.count += 1;
        }
        self.slots[slot] = (phrase, byte, index);
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn clear(&mut self) {
        self.slots.fill((0, 0, LZ78::EMPTY));
        self.count = 0;
    }
}

impl LZ78 {
    pub const NAME: &'static str = "lz78";
    /// The bytes one token spends: a phrase index and the byte that follows it.
    pub const TOKEN: usize = 5;
    /// The index that stands for the empty phrase.
    pub const EMPTY: u32 = 0;

    /// The number of phrases the dictionary holds before it starts over.
    pub fn dictionary(&self) -> usize {
        self.dictionary.max(2)
    }

    /// Encodes `data` as phrase and literal pairs, which is what the builtin codec writes.
    pub fn encode(&self, data: &[u8]) -> Result<Vec<u8>, LZ78Error> {
        let mut phrases = LZ78Dictionary::new(self.dictionary().min(data.len() + 1));
        let mut output = Vec::with_capacity(data.len() / 2 + Self::TOKEN);
        let mut current = Self::EMPTY;
        for byte in data {
            match phrases.get(current, *byte) {
                Some(index) => current = index,
                None => {
                    output.extend_from_slice(&current.to_le_bytes());
                    output.push(*byte);
                    match phrases.len() + 1 < self.dictionary() {
                        true => phrases.insert(current, *byte, phrases.len() as u32 + 1),
                        false => phrases.clear(),
                    }
                    current = Self::EMPTY;
                }
            }
        }
        if current != Self::EMPTY {
            output.extend_from_slice(&current.to_le_bytes());
        }
        Ok(output)
    }

    /// Decodes phrase and literal pairs, which is what the builtin codec reads.
    pub fn decode(&self, data: &[u8]) -> Result<Vec<u8>, LZ78Error> {
        let mut phrases: Vec<(u32, u8)> = Vec::new();
        let mut output = Vec::with_capacity(data.len() * 2);
        let mut offset = 0;
        while offset < data.len() {
            if offset + 4 > data.len() {
                return Err(LZ78Error::Truncated);
            }
            let index = u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]);
            if index as usize > phrases.len() {
                return Err(LZ78Error::Format);
            }
            let length = Self::length(&phrases, index);
            offset += 4;
            if offset == data.len() {
                if self.limit.is_some_and(|limit| output.len() + length > limit) {
                    return Err(LZ78Error::Limit);
                }
                Self::unfold(&phrases, index, &mut output);
                return Ok(output);
            }
            let byte = data[offset];
            offset += 1;
            if self.limit.is_some_and(|limit| output.len() + length + 1 > limit) {
                return Err(LZ78Error::Limit);
            }
            Self::unfold(&phrases, index, &mut output);
            output.push(byte);
            match phrases.len() + 1 < self.dictionary() {
                true => phrases.push((index, byte)),
                false => phrases.clear(),
            }
        }
        Ok(output)
    }

    /// The bytes a phrase index stands for.
    pub fn phrase(phrases: &[(u32, u8)], index: u32) -> Vec<u8> {
        let mut bytes = Vec::new();
        Self::unfold(phrases, index, &mut bytes);
        bytes
    }

    /// Writes the bytes a phrase index stands for onto the end of `output`.
    pub fn unfold(phrases: &[(u32, u8)], index: u32, output: &mut Vec<u8>) {
        let start = output.len();
        let mut current = index;
        while current != Self::EMPTY {
            let (parent, byte) = phrases[current as usize - 1];
            output.push(byte);
            current = parent;
        }
        output[start..].reverse();
    }

    /// The number of bytes a phrase index stands for.
    pub fn length(phrases: &[(u32, u8)], index: u32) -> usize {
        let mut length = 0;
        let mut current = index;
        while current != Self::EMPTY {
            length += 1;
            current = phrases[current as usize - 1].0;
        }
        length
    }

    pub fn request(&self, direction: CodecDirection) -> CodecProviderRequest<'_> {
        CodecProviderRequest::new(Self::NAME, direction).with_limit(self.limit)
    }

    pub fn encoder(&self) -> LZ78Encoder {
        LZ78Encoder::new(self.clone())
    }

    pub fn decoder(&self) -> LZ78Decoder {
        LZ78Decoder::new(self.clone())
    }

    pub fn compress(&self, data: &[u8]) -> Result<Vec<u8>, LZ78Error> {
        match CodecProviders::transform(&self.request(CodecDirection::Encode), data)? {
            Some(output) => Ok(output),
            None => self.encode(data),
        }
    }

    pub fn decompress(&self, data: &[u8]) -> Result<Vec<u8>, LZ78Error> {
        match CodecProviders::transform(&self.request(CodecDirection::Decode), data)? {
            Some(output) => Ok(output),
            None => self.decode(data),
        }
    }
}

#[derive(Debug)]
pub struct LZ78Encoder {
    options: LZ78,
    input: Vec<u8>,
    backend: ProviderBackend<dyn CodecProvider>,
}

impl LZ78Encoder {
    pub fn new(options: LZ78) -> Self {
        match CodecProviders::backend(&options.request(CodecDirection::Encode)) {
            ProviderBackend::Builtin => Self { options, input: Vec::new(), backend: ProviderBackend::Builtin },
            backend => Self { options, input: Vec::new(), backend },
        }
    }

    pub fn options(&self) -> &LZ78 {
        &self.options
    }

    /// Holds `data` until the stream is finalized, which is when the builtin codec runs.
    pub fn update(&mut self, data: &[u8]) -> Result<Vec<u8>, LZ78Error> {
        match &self.backend {
            ProviderBackend::Builtin => {
                self.input.extend_from_slice(data);
                Ok(Vec::new())
            }
            ProviderBackend::Handle { provider, handle } => Ok(provider.update(*handle, data)?),
        }
    }

    pub fn finalize(self) -> Result<Vec<u8>, LZ78Error> {
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
pub struct LZ78Decoder {
    options: LZ78,
    input: Vec<u8>,
    backend: ProviderBackend<dyn CodecProvider>,
}

impl LZ78Decoder {
    pub fn new(options: LZ78) -> Self {
        match CodecProviders::backend(&options.request(CodecDirection::Decode)) {
            ProviderBackend::Builtin => Self { options, input: Vec::new(), backend: ProviderBackend::Builtin },
            backend => Self { options, input: Vec::new(), backend },
        }
    }

    pub fn options(&self) -> &LZ78 {
        &self.options
    }

    /// Holds `data` until the stream is finalized, which is when the builtin codec runs.
    pub fn update(&mut self, data: &[u8]) -> Result<Vec<u8>, LZ78Error> {
        match &self.backend {
            ProviderBackend::Builtin => {
                self.input.extend_from_slice(data);
                Ok(Vec::new())
            }
            ProviderBackend::Handle { provider, handle } => Ok(provider.update(*handle, data)?),
        }
    }

    pub fn finalize(self) -> Result<Vec<u8>, LZ78Error> {
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

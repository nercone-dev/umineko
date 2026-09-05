use alloc::vec;
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
    pub const MAXIMUM_CONTEXT: u8 = 8;
    pub const MAXIMUM_POSITION: u8 = 4;

    pub fn encode(&self) -> [u8; 5] {
        let mut encoded = [0; 5];
        encoded[0] = (self.position * 5 + self.literal_position) * 9 + self.literal_context;
        encoded[1..].copy_from_slice(&self.dictionary.to_le_bytes());
        encoded
    }

    pub fn decode(data: &[u8; 5]) -> Result<Self, LZMAError> {
        let packed = data[0];
        if packed >= 9 * 5 * 5 {
            return Err(LZMAError::Properties);
        }
        let properties = Self {
            literal_context: packed % 9,
            literal_position: (packed / 9) % 5,
            position: packed / 45,
            dictionary: u32::from_le_bytes([data[1], data[2], data[3], data[4]]),
        };
        match properties.literal_context <= Self::MAXIMUM_CONTEXT && properties.literal_position <= Self::MAXIMUM_POSITION && properties.position <= Self::MAXIMUM_POSITION {
            true => Ok(properties),
            false => Err(LZMAError::Properties),
        }
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
            None => self.encode(data),
        }
    }

    pub fn decompress(&self, data: &[u8]) -> Result<Vec<u8>, LZMAError> {
        match CodecProviders::transform(&self.request(CodecDirection::Decode), data)? {
            Some(output) => Ok(output),
            None => self.decode(data),
        }
    }
}

/// The adaptive bit models one LZMA stream carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LZMAModel {
    pub properties: LZMAProperties,
    pub literal: Vec<u16>,
    pub match_bits: Vec<u16>,
    pub rep_long: Vec<u16>,
    pub rep: [u16; 12],
    pub rep_first: [u16; 12],
    pub rep_second: [u16; 12],
    pub rep_third: [u16; 12],
    pub slots: [[u16; 64]; 4],
    pub positions: [u16; 115],
    pub aligned: [u16; 16],
    pub lengths: LZMALengths,
    pub rep_lengths: LZMALengths,
}

impl LZMAModel {
    /// The value a bit model starts at, which is an even chance.
    pub const INITIAL: u16 = 1 << 10;
    pub const TOTAL_BITS: u32 = 11;
    pub const MOVE_BITS: u32 = 5;
    pub const STATES: usize = 12;
    /// The number of position bits the models are spread over.
    pub const POSITION_BITS: usize = 4;
    /// The shortest match a stream carries.
    pub const MINIMUM_MATCH: usize = 2;
    /// The slot from which distances carry aligned bits.
    pub const ALIGN_SLOT: usize = 14;
    pub const ALIGN_BITS: u32 = 4;
    /// The distance that stands for the end of the stream.
    pub const MARKER: u32 = 0xFFFF_FFFF;

    pub fn new(properties: LZMAProperties) -> Self {
        Self {
            properties,
            literal: vec![Self::INITIAL; 0x300 << (properties.literal_context + properties.literal_position)],
            match_bits: vec![Self::INITIAL; Self::STATES << Self::POSITION_BITS],
            rep_long: vec![Self::INITIAL; Self::STATES << Self::POSITION_BITS],
            rep: [Self::INITIAL; 12],
            rep_first: [Self::INITIAL; 12],
            rep_second: [Self::INITIAL; 12],
            rep_third: [Self::INITIAL; 12],
            slots: [[Self::INITIAL; 64]; 4],
            positions: [Self::INITIAL; 115],
            aligned: [Self::INITIAL; 16],
            lengths: LZMALengths::new(),
            rep_lengths: LZMALengths::new(),
        }
    }

    /// The state a literal moves the coder into.
    pub fn after_literal(state: usize) -> usize {
        match state {
            0..=3 => 0,
            4..=9 => state - 3,
            _ => state - 6,
        }
    }

    /// The state a fresh match moves the coder into.
    pub fn after_match(state: usize) -> usize {
        match state < 7 {
            true => 7,
            false => 10,
        }
    }

    /// The state a repeated match moves the coder into.
    pub fn after_rep(state: usize) -> usize {
        match state < 7 {
            true => 8,
            false => 11,
        }
    }

    /// The state a one byte repeat moves the coder into.
    pub fn after_short(state: usize) -> usize {
        match state < 7 {
            true => 9,
            false => 11,
        }
    }

    /// The model a literal is coded with, which follows the byte before it.
    pub fn literal_state(&self, total: usize, previous: u8) -> usize {
        let position = total & ((1 << self.properties.literal_position) - 1);
        (position << self.properties.literal_context) + ((previous as u32) >> (8 - self.properties.literal_context)) as usize
    }
}

/// The bit models one length is coded with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LZMALengths {
    pub choice: u16,
    pub choice_second: u16,
    pub low: [[u16; 8]; 16],
    pub middle: [[u16; 8]; 16],
    pub high: [u16; 256],
}

impl LZMALengths {
    pub fn new() -> Self {
        Self {
            choice: LZMAModel::INITIAL,
            choice_second: LZMAModel::INITIAL,
            low: [[LZMAModel::INITIAL; 8]; 16],
            middle: [[LZMAModel::INITIAL; 8]; 16],
            high: [LZMAModel::INITIAL; 256],
        }
    }
}

impl Default for LZMALengths {
    fn default() -> Self {
        Self::new()
    }
}

/// Reads bits out of an LZMA range coded stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LZMARangeDecoder<'a> {
    storage: &'a [u8],
    position: usize,
    range: u32,
    code: u32,
}

impl<'a> LZMARangeDecoder<'a> {
    pub const TOP: u32 = 1 << 24;

    pub fn new(storage: &'a [u8]) -> Result<Self, LZMAError> {
        if storage.len() < 5 || storage[0] != 0 {
            return Err(LZMAError::Format);
        }
        let code = u32::from_be_bytes([storage[1], storage[2], storage[3], storage[4]]);
        Ok(Self { storage, position: 5, range: u32::MAX, code })
    }

    pub fn byte(&mut self) -> u8 {
        let byte = self.storage.get(self.position).copied().unwrap_or(0);
        self.position += 1;
        byte
    }

    pub fn normalize(&mut self) {
        if self.range < Self::TOP {
            self.range <<= 8;
            self.code = (self.code << 8) | self.byte() as u32;
        }
    }

    pub fn bit(&mut self, model: &mut u16) -> u32 {
        let bound = (self.range >> LZMAModel::TOTAL_BITS) * *model as u32;
        let bit = match self.code < bound {
            true => {
                self.range = bound;
                *model += ((1 << LZMAModel::TOTAL_BITS) - *model) >> LZMAModel::MOVE_BITS;
                0
            }
            false => {
                self.range -= bound;
                self.code -= bound;
                *model -= *model >> LZMAModel::MOVE_BITS;
                1
            }
        };
        self.normalize();
        bit
    }

    /// Reads bits that carry no model.
    pub fn direct(&mut self, bits: u32) -> u32 {
        let mut value: u32 = 0;
        for _ in 0..bits {
            self.range >>= 1;
            self.code = self.code.wrapping_sub(self.range);
            let mask = 0u32.wrapping_sub(self.code >> 31);
            self.code = self.code.wrapping_add(self.range & mask);
            self.normalize();
            value = (value << 1).wrapping_add(mask.wrapping_add(1));
        }
        value
    }

    /// Reads a symbol from a bit tree, most significant bit first.
    pub fn tree(&mut self, models: &mut [u16], bits: u32) -> u32 {
        let mut index = 1;
        for _ in 0..bits {
            index = (index << 1) + self.bit(&mut models[index as usize]);
        }
        index - (1 << bits)
    }

    /// Reads a symbol from a bit tree, least significant bit first.
    pub fn tree_reverse(&mut self, models: &mut [u16], bits: u32) -> u32 {
        let mut index = 1;
        let mut value = 0;
        for step in 0..bits {
            let bit = self.bit(&mut models[index as usize]);
            index = (index << 1) + bit;
            value |= bit << step;
        }
        value
    }

    pub fn length(&mut self, lengths: &mut LZMALengths, position: usize) -> u32 {
        match self.bit(&mut lengths.choice) {
            0 => self.tree(&mut lengths.low[position], 3),
            _ => match self.bit(&mut lengths.choice_second) {
                0 => 8 + self.tree(&mut lengths.middle[position], 3),
                _ => 16 + self.tree(&mut lengths.high, 8),
            },
        }
    }

    /// Whether the coder sits exactly at the end of a well formed stream.
    pub fn finished(&self) -> bool {
        self.code == 0
    }

    pub fn position(&self) -> usize {
        self.position
    }
}

/// Writes bits into an LZMA range coded stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LZMARangeEncoder {
    storage: Vec<u8>,
    low: u64,
    range: u32,
    cache: u8,
    held: u64,
}

impl LZMARangeEncoder {
    pub const TOP: u32 = 1 << 24;

    pub fn new() -> Self {
        Self { storage: Vec::new(), low: 0, range: u32::MAX, cache: 0, held: 1 }
    }

    pub fn shift(&mut self) {
        if (self.low >> 32) != 0 || self.low < 0xFF00_0000 {
            let carry = (self.low >> 32) as u8;
            let mut byte = self.cache;
            loop {
                self.storage.push(byte.wrapping_add(carry));
                byte = 0xFF;
                self.held -= 1;
                if self.held == 0 {
                    break;
                }
            }
            self.cache = (self.low >> 24) as u8;
        }
        self.held += 1;
        self.low = ((self.low as u32) << 8) as u64;
    }

    pub fn normalize(&mut self) {
        if self.range < Self::TOP {
            self.range <<= 8;
            self.shift();
        }
    }

    pub fn bit(&mut self, model: &mut u16, bit: u32) {
        let bound = (self.range >> LZMAModel::TOTAL_BITS) * *model as u32;
        match bit {
            0 => {
                self.range = bound;
                *model += ((1 << LZMAModel::TOTAL_BITS) - *model) >> LZMAModel::MOVE_BITS;
            }
            _ => {
                self.low += bound as u64;
                self.range -= bound;
                *model -= *model >> LZMAModel::MOVE_BITS;
            }
        }
        self.normalize();
    }

    /// Writes bits that carry no model.
    pub fn direct(&mut self, value: u32, bits: u32) {
        for step in (0..bits).rev() {
            self.range >>= 1;
            if (value >> step) & 1 == 1 {
                self.low += self.range as u64;
            }
            self.normalize();
        }
    }

    /// Writes a symbol into a bit tree, most significant bit first.
    pub fn tree(&mut self, models: &mut [u16], bits: u32, symbol: u32) {
        let mut index = 1;
        for step in (0..bits).rev() {
            let bit = (symbol >> step) & 1;
            self.bit(&mut models[index as usize], bit);
            index = (index << 1) + bit;
        }
    }

    /// Writes a symbol into a bit tree, least significant bit first.
    pub fn tree_reverse(&mut self, models: &mut [u16], bits: u32, symbol: u32) {
        let mut index = 1;
        for step in 0..bits {
            let bit = (symbol >> step) & 1;
            self.bit(&mut models[index as usize], bit);
            index = (index << 1) + bit;
        }
    }

    pub fn length(&mut self, lengths: &mut LZMALengths, position: usize, length: u32) {
        match length {
            0..=7 => {
                self.bit(&mut lengths.choice, 0);
                self.tree(&mut lengths.low[position], 3, length);
            }
            8..=15 => {
                self.bit(&mut lengths.choice, 1);
                self.bit(&mut lengths.choice_second, 0);
                self.tree(&mut lengths.middle[position], 3, length - 8);
            }
            _ => {
                self.bit(&mut lengths.choice, 1);
                self.bit(&mut lengths.choice_second, 1);
                self.tree(&mut lengths.high, 8, length - 16);
            }
        }
    }

    pub fn finish(mut self) -> Vec<u8> {
        for _ in 0..5 {
            self.shift();
        }
        self.storage
    }
}

impl Default for LZMARangeEncoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Finds the longest earlier copy of the bytes at a position, through a chain of hash buckets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LZMAMatcher {
    window: usize,
    probes: usize,
    head: Vec<u32>,
    chain: Vec<u32>,
}

impl LZMAMatcher {
    pub const HASH_BITS: u32 = 16;
    pub const HASH_SIZE: usize = 1 << Self::HASH_BITS;
    pub const MINIMUM: usize = 3;
    pub const MAXIMUM: usize = 273;

    /// The fewest buckets a search spreads its positions over.
    pub const MINIMUM_HASH_SIZE: usize = 256;

    /// A matcher whose tables hold whichever is shorter: one window, or the whole of `length` bytes.
    pub fn new(window: usize, probes: usize, length: usize) -> Self {
        let window = window.clamp(1, length.max(1));
        let buckets = window.next_power_of_two().clamp(Self::MINIMUM_HASH_SIZE, Self::HASH_SIZE);
        Self { window, probes: probes.max(1), head: vec![0; buckets], chain: vec![0; window.next_power_of_two()] }
    }

    /// The number of buckets positions spread over, which the window sets.
    pub fn buckets(&self) -> usize {
        self.head.len()
    }

    pub fn hash(&self, data: &[u8], offset: usize) -> usize {
        match offset + Self::MINIMUM <= data.len() {
            true => (u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], 0]).wrapping_mul(2654435761) >> (32 - Self::HASH_BITS)) as usize & (self.head.len() - 1),
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

    pub fn find(&self, data: &[u8], offset: usize) -> Option<(usize, usize)> {
        let available = (data.len() - offset).min(Self::MAXIMUM);
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

impl LZMA {
    /// The bytes the header of a standalone stream spends.
    pub const HEADER: usize = 13;
    /// The size field that says the length of the content is not known ahead of time.
    pub const UNKNOWN: u64 = u64::MAX;

    /// The number of earlier positions one search walks, which the level sets.
    pub fn probes(&self) -> usize {
        (self.level.max(1) as usize) * 16
    }

    /// The slot, the bits below it and their count, that a distance is written as.
    pub fn slot(distance: u32) -> (u32, u32, u32) {
        match distance < 4 {
            true => (distance, 0, 0),
            false => {
                let bits = 31 - distance.leading_zeros();
                let slot = (bits << 1) | ((distance >> (bits - 1)) & 1);
                let direct = bits - 1;
                (slot, distance - ((2 | (slot & 1)) << direct), direct)
            }
        }
    }

    /// Encodes `data` as a standalone stream, which is what the builtin codec writes.
    pub fn encode(&self, data: &[u8]) -> Result<Vec<u8>, LZMAError> {
        let mut output = self.properties.encode().to_vec();
        output.extend_from_slice(&(data.len() as u64).to_le_bytes());
        output.extend_from_slice(&self.compress_body(data)?);
        Ok(output)
    }

    /// Encodes the range coded body of a stream, without the header before it.
    pub fn compress_body(&self, data: &[u8]) -> Result<Vec<u8>, LZMAError> {
        let mut model = LZMAModel::new(self.properties);
        let mut coder = LZMARangeEncoder::new();
        let mut matcher = LZMAMatcher::new(self.properties.dictionary as usize, self.probes(), data.len());
        let mut state = 0;
        let mut reps = [0u32; 4];
        let mut offset = 0;
        while offset < data.len() {
            let position = offset & ((1 << self.properties.position) - 1);
            let found = match self.level {
                0 => None,
                _ => matcher.find(data, offset),
            };
            match found {
                Some((distance, length)) => {
                    coder.bit(&mut model.match_bits[(state << LZMAModel::POSITION_BITS) + position], 1);
                    let repeat = reps.iter().position(|rep| *rep as usize + 1 == distance);
                    match repeat {
                        Some(index) => {
                            coder.bit(&mut model.rep[state], 1);
                            match index {
                                0 => {
                                    coder.bit(&mut model.rep_first[state], 0);
                                    coder.bit(&mut model.rep_long[(state << LZMAModel::POSITION_BITS) + position], 1);
                                }
                                1 => {
                                    coder.bit(&mut model.rep_first[state], 1);
                                    coder.bit(&mut model.rep_second[state], 0);
                                }
                                2 => {
                                    coder.bit(&mut model.rep_first[state], 1);
                                    coder.bit(&mut model.rep_second[state], 1);
                                    coder.bit(&mut model.rep_third[state], 0);
                                }
                                _ => {
                                    coder.bit(&mut model.rep_first[state], 1);
                                    coder.bit(&mut model.rep_second[state], 1);
                                    coder.bit(&mut model.rep_third[state], 1);
                                }
                            }
                            let carried = reps[index];
                            for step in (1..=index).rev() {
                                reps[step] = reps[step - 1];
                            }
                            reps[0] = carried;
                            coder.length(&mut model.rep_lengths, position, (length - LZMAModel::MINIMUM_MATCH) as u32);
                            state = LZMAModel::after_rep(state);
                        }
                        None => {
                            coder.bit(&mut model.rep[state], 0);
                            coder.length(&mut model.lengths, position, (length - LZMAModel::MINIMUM_MATCH) as u32);
                            let index = (length - LZMAModel::MINIMUM_MATCH).min(3);
                            let (slot, below, bits) = Self::slot(distance as u32 - 1);
                            coder.tree(&mut model.slots[index], 6, slot);
                            if slot >= 4 {
                                match (slot as usize) < LZMAModel::ALIGN_SLOT {
                                    true => {
                                        let base = ((2 | (slot & 1)) << bits) as usize - slot as usize;
                                        coder.tree_reverse(&mut model.positions[base..], bits, below);
                                    }
                                    false => {
                                        coder.direct(below >> LZMAModel::ALIGN_BITS, bits - LZMAModel::ALIGN_BITS);
                                        coder.tree_reverse(&mut model.aligned, LZMAModel::ALIGN_BITS, below & 0x0F);
                                    }
                                }
                            }
                            reps = [distance as u32 - 1, reps[0], reps[1], reps[2]];
                            state = LZMAModel::after_match(state);
                        }
                    }
                    for step in 0..length {
                        matcher.insert(data, offset + step);
                    }
                    offset += length;
                }
                None => {
                    coder.bit(&mut model.match_bits[(state << LZMAModel::POSITION_BITS) + position], 0);
                    let previous = match offset {
                        0 => 0,
                        offset => data[offset - 1],
                    };
                    let literal = model.literal_state(offset, previous);
                    let models = &mut model.literal[0x300 * literal..0x300 * (literal + 1)];
                    let symbol = data[offset] as u32;
                    match state >= 7 {
                        true => {
                            let mut matched = data[offset - reps[0] as usize - 1] as u32;
                            let mut index = 1;
                            let mut step = 8;
                            while step > 0 {
                                step -= 1;
                                let bit = (symbol >> step) & 1;
                                let expected = (matched >> 7) & 1;
                                matched = (matched << 1) & 0xFF;
                                coder.bit(&mut models[(((1 + expected) << 8) + index) as usize], bit);
                                index = (index << 1) | bit;
                                if expected != bit {
                                    break;
                                }
                            }
                            while step > 0 {
                                step -= 1;
                                let bit = (symbol >> step) & 1;
                                coder.bit(&mut models[index as usize], bit);
                                index = (index << 1) | bit;
                            }
                        }
                        false => {
                            let mut index = 1;
                            for step in (0..8).rev() {
                                let bit = (symbol >> step) & 1;
                                coder.bit(&mut models[index as usize], bit);
                                index = (index << 1) | bit;
                            }
                        }
                    }
                    state = LZMAModel::after_literal(state);
                    matcher.insert(data, offset);
                    offset += 1;
                }
            }
        }
        Ok(coder.finish())
    }

    /// Decodes a standalone stream, which is what the builtin codec reads.
    pub fn decode(&self, data: &[u8]) -> Result<Vec<u8>, LZMAError> {
        if data.len() < Self::HEADER {
            return Err(LZMAError::Truncated);
        }
        let mut header = [0; 5];
        header.copy_from_slice(&data[..5]);
        let properties = LZMAProperties::decode(&header)?;
        let mut size = [0; 8];
        size.copy_from_slice(&data[5..13]);
        let size = u64::from_le_bytes(size);
        self.decompress_body(&data[Self::HEADER..], properties, size)
    }

    /// Decodes the range coded body of a stream, whose header has already been read.
    pub fn decompress_body(&self, data: &[u8], properties: LZMAProperties, size: u64) -> Result<Vec<u8>, LZMAError> {
        let mut model = LZMAModel::new(properties);
        let mut coder = LZMARangeDecoder::new(data)?;
        let mut output: Vec<u8> = Vec::new();
        let mut state = 0;
        let mut reps = [0u32; 4];
        loop {
            if size != Self::UNKNOWN && output.len() as u64 == size {
                return Ok(output);
            }
            if coder.position() > data.len() {
                return Err(LZMAError::Truncated);
            }
            if self.limit.is_some_and(|limit| output.len() > limit) {
                return Err(LZMAError::Limit);
            }
            let position = output.len() & ((1 << properties.position) - 1);
            if coder.bit(&mut model.match_bits[(state << LZMAModel::POSITION_BITS) + position]) == 0 {
                let previous = output.last().copied().unwrap_or(0);
                let literal = model.literal_state(output.len(), previous);
                let models = &mut model.literal[0x300 * literal..0x300 * (literal + 1)];
                let mut symbol = 1u32;
                if state >= 7 {
                    let mut matched = *output.get(output.len().wrapping_sub(reps[0] as usize + 1)).ok_or(LZMAError::Format)? as u32;
                    while symbol < 0x100 {
                        let expected = (matched >> 7) & 1;
                        matched = (matched << 1) & 0xFF;
                        let bit = coder.bit(&mut models[(((1 + expected) << 8) + symbol) as usize]);
                        symbol = (symbol << 1) | bit;
                        if expected != bit {
                            break;
                        }
                    }
                }
                while symbol < 0x100 {
                    symbol = (symbol << 1) | coder.bit(&mut models[symbol as usize]);
                }
                output.push(symbol as u8);
                state = LZMAModel::after_literal(state);
                continue;
            }
            let length;
            if coder.bit(&mut model.rep[state]) != 0 {
                if output.is_empty() {
                    return Err(LZMAError::Format);
                }
                if coder.bit(&mut model.rep_first[state]) == 0 {
                    if coder.bit(&mut model.rep_long[(state << LZMAModel::POSITION_BITS) + position]) == 0 {
                        state = LZMAModel::after_short(state);
                        let byte = *output.get(output.len().wrapping_sub(reps[0] as usize + 1)).ok_or(LZMAError::Format)?;
                        output.push(byte);
                        continue;
                    }
                } else {
                    let distance = match coder.bit(&mut model.rep_second[state]) {
                        0 => reps[1],
                        _ => {
                            let distance = match coder.bit(&mut model.rep_third[state]) {
                                0 => reps[2],
                                _ => {
                                    let third = reps[3];
                                    reps[3] = reps[2];
                                    third
                                }
                            };
                            reps[2] = reps[1];
                            distance
                        }
                    };
                    reps[1] = reps[0];
                    reps[0] = distance;
                }
                length = coder.length(&mut model.rep_lengths, position);
                state = LZMAModel::after_rep(state);
            } else {
                reps = [reps[0], reps[0], reps[1], reps[2]];
                length = coder.length(&mut model.lengths, position);
                state = LZMAModel::after_match(state);
                let index = length.min(3) as usize;
                let slot = coder.tree(&mut model.slots[index], 6);
                reps[0] = match slot < 4 {
                    true => slot,
                    false => {
                        let bits = (slot >> 1) - 1;
                        let base = (2 | (slot & 1)) << bits;
                        match (slot as usize) < LZMAModel::ALIGN_SLOT {
                            true => base + coder.tree_reverse(&mut model.positions[(base - slot) as usize..], bits),
                            false => base + (coder.direct(bits - LZMAModel::ALIGN_BITS) << LZMAModel::ALIGN_BITS) + coder.tree_reverse(&mut model.aligned, LZMAModel::ALIGN_BITS),
                        }
                    }
                };
                if reps[0] == LZMAModel::MARKER {
                    return Ok(output);
                }
                if reps[0] as usize >= output.len() {
                    return Err(LZMAError::Format);
                }
            }
            let length = length as usize + LZMAModel::MINIMUM_MATCH;
            if self.limit.is_some_and(|limit| output.len() + length > limit) {
                return Err(LZMAError::Limit);
            }
            let start = output.len() - reps[0] as usize - 1;
            for step in 0..length {
                output.push(output[start + step]);
                if size != Self::UNKNOWN && output.len() as u64 == size {
                    break;
                }
            }
        }
    }
}

#[derive(Debug)]
pub struct LZMAEncoder {
    options: LZMA,
    input: Vec<u8>,
    backend: ProviderBackend<dyn CodecProvider>,
}

impl LZMAEncoder {
    pub fn new(options: LZMA) -> Self {
        match CodecProviders::backend(&options.request(CodecDirection::Encode)) {
            ProviderBackend::Builtin => Self { options, input: Vec::new(), backend: ProviderBackend::Builtin },
            backend => Self { options, input: Vec::new(), backend },
        }
    }

    pub fn options(&self) -> &LZMA {
        &self.options
    }

    /// Holds `data` until the stream is finalized, which is when the builtin codec runs.
    pub fn update(&mut self, data: &[u8]) -> Result<Vec<u8>, LZMAError> {
        match &self.backend {
            ProviderBackend::Builtin => {
                self.input.extend_from_slice(data);
                Ok(Vec::new())
            }
            ProviderBackend::Handle { provider, handle } => Ok(provider.update(*handle, data)?),
        }
    }

    pub fn finalize(self) -> Result<Vec<u8>, LZMAError> {
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
pub struct LZMADecoder {
    options: LZMA,
    input: Vec<u8>,
    backend: ProviderBackend<dyn CodecProvider>,
}

impl LZMADecoder {
    pub fn new(options: LZMA) -> Self {
        match CodecProviders::backend(&options.request(CodecDirection::Decode)) {
            ProviderBackend::Builtin => Self { options, input: Vec::new(), backend: ProviderBackend::Builtin },
            backend => Self { options, input: Vec::new(), backend },
        }
    }

    pub fn options(&self) -> &LZMA {
        &self.options
    }

    /// Holds `data` until the stream is finalized, which is when the builtin codec runs.
    pub fn update(&mut self, data: &[u8]) -> Result<Vec<u8>, LZMAError> {
        match &self.backend {
            ProviderBackend::Builtin => {
                self.input.extend_from_slice(data);
                Ok(Vec::new())
            }
            ProviderBackend::Handle { provider, handle } => Ok(provider.update(*handle, data)?),
        }
    }

    pub fn finalize(self) -> Result<Vec<u8>, LZMAError> {
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

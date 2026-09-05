use alloc::vec;
use alloc::vec::Vec;
use crate::contexts::BrotliContext;
use crate::dictionary::BrotliDictionary;
use crate::errors::BrotliError;
use crate::transforms::BrotliTransform;

use umineko_codec_huffman::HuffmanTree;
use umineko_codec_lz77::LZ77Matcher;

use umineko_helpers::provider::{CodecDirection, CodecProvider, CodecProviderRequest, CodecProviders, ProviderBackend};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Brotli {
    pub quality: u8,
    pub window: u8,
        pub limit: Option<usize>,
}

impl Default for Brotli {
    fn default() -> Self {
        Self {
            quality: 11,
            window: 22,
            limit: None,
        }
    }
}

impl Brotli {
    pub const NAME: &'static str = "brotli";

    pub fn request(&self, direction: CodecDirection) -> CodecProviderRequest<'_> {
        CodecProviderRequest::new(Self::NAME, direction).with_level(self.quality as i32).with_window(self.window).with_limit(self.limit)
    }

    pub fn encoder(&self) -> BrotliEncoder {
        BrotliEncoder::new(self.clone())
    }

    pub fn decoder(&self) -> BrotliDecoder {
        BrotliDecoder::new(self.clone())
    }

    pub fn compress(&self, data: &[u8]) -> Result<Vec<u8>, BrotliError> {
        match CodecProviders::transform(&self.request(CodecDirection::Encode), data)? {
            Some(output) => Ok(output),
            None => self.encode(data),
        }
    }

    pub fn decompress(&self, data: &[u8]) -> Result<Vec<u8>, BrotliError> {
        match CodecProviders::transform(&self.request(CodecDirection::Decode), data)? {
            Some(output) => Ok(output),
            None => self.decode(data),
        }
    }
}

/// A point in a stream, which one shape of a meta-block can be wound back to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BrotliMark {
    pub bytes: usize,
    pub holding: u64,
    pub held: u8,
}

/// Writes a brotli bit stream, least significant bit first.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BrotliWriter {
    storage: Vec<u8>,
    holding: u64,
    held: u8,
}

impl BrotliWriter {
    pub fn new() -> Self {
        Self { storage: Vec::new(), holding: 0, held: 0 }
    }

    pub fn write(&mut self, bits: u64, length: u8) {
        if length == 0 {
            return;
        }
        self.holding |= (bits & (u64::MAX >> (64 - length))) << self.held;
        self.held += length;
        while self.held >= 8 {
            self.storage.push(self.holding as u8);
            self.holding >>= 8;
            self.held -= 8;
        }
    }

    /// Writes a prefix code, whose bits travel most significant first.
    pub fn code(&mut self, code: u16, length: u8) {
        match length {
            0 => {}
            length => self.write((code.reverse_bits() >> (16 - length)) as u64, length),
        }
    }

    /// The bits the stream carries so far, which weighs one shape of a meta-block against another.
    pub fn length(&self) -> usize {
        self.storage.len() * 8 + self.held as usize
    }

    /// The point the stream stands at, which one shape of a meta-block can be dropped back to.
    pub fn mark(&self) -> BrotliMark {
        BrotliMark { bytes: self.storage.len(), holding: self.holding, held: self.held }
    }

    /// Drops everything written since `mark`.
    pub fn rewind(&mut self, mark: BrotliMark) {
        self.storage.truncate(mark.bytes);
        (self.holding, self.held) = (mark.holding, mark.held);
    }

    /// Pads the stream with zero bits up to the next byte.
    pub fn align(&mut self) {
        if self.held != 0 {
            let padding = 8 - self.held;
            self.write(0, padding);
        }
    }

    pub fn bytes(&mut self, data: &[u8]) {
        self.align();
        self.storage.extend_from_slice(data);
    }

    pub fn finish(mut self) -> Vec<u8> {
        self.align();
        self.storage
    }
}

/// Reads a brotli bit stream, least significant bit first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrotliReader<'a> {
    storage: &'a [u8],
    position: usize,
}

impl<'a> BrotliReader<'a> {
    pub fn new(storage: &'a [u8]) -> Self {
        Self { storage, position: 0 }
    }

    pub fn bit(&mut self) -> Result<u64, BrotliError> {
        let byte = self.storage.get(self.position / 8).ok_or(BrotliError::Truncated)?;
        let bit = (byte >> (self.position % 8)) & 1;
        self.position += 1;
        Ok(bit as u64)
    }

    pub fn read(&mut self, length: u8) -> Result<u64, BrotliError> {
        let (mut value, mut filled) = (0u64, 0u8);
        while filled < length {
            let byte = *self.storage.get(self.position / 8).ok_or(BrotliError::Truncated)?;
            let used = (self.position % 8) as u8;
            let taken = (8 - used).min(length - filled);
            value |= (((byte >> used) as u64) & (u64::MAX >> (64 - taken))) << filled;
            self.position += taken as usize;
            filled += taken;
        }
        Ok(value)
    }

    /// Drops the bits up to the next byte and returns that byte offset.
    pub fn align(&mut self) -> usize {
        self.position = self.position.div_ceil(8) * 8;
        self.position / 8
    }

    pub fn take(&mut self, length: usize) -> Result<&'a [u8], BrotliError> {
        let start = self.align();
        let end = start.checked_add(length).ok_or(BrotliError::Truncated)?;
        if end > self.storage.len() {
            return Err(BrotliError::Truncated);
        }
        self.position = end * 8;
        Ok(&self.storage[start..end])
    }

    pub fn position(&self) -> usize {
        self.position
    }

    pub fn finished(&self) -> bool {
        self.position.div_ceil(8) >= self.storage.len()
    }
}

/// A prefix code, which names one symbol on its own or a canonical tree of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrotliCode {
    Single(usize),
    Tree(HuffmanTree),
}

impl BrotliCode {
    /// The code the stream carries, over an alphabet of `alphabet` symbols.
    pub fn read(reader: &mut BrotliReader<'_>, alphabet: usize) -> Result<Self, BrotliError> {
        match reader.read(2)? {
            1 => Self::simple(reader, alphabet),
            skip => Self::complex(reader, alphabet, skip as usize),
        }
    }

    /// The code a simple description names, which carries one to four symbols.
    pub fn simple(reader: &mut BrotliReader<'_>, alphabet: usize) -> Result<Self, BrotliError> {
        let count = reader.read(2)? as usize + 1;
        let bits = Brotli::width(alphabet);
        let mut symbols = Vec::with_capacity(count);
        for _ in 0..count {
            let symbol = reader.read(bits)? as usize;
            if symbol >= alphabet || symbols.contains(&symbol) {
                return Err(BrotliError::Format);
            }
            symbols.push(symbol);
        }
        if count == 1 {
            return Ok(Self::Single(symbols[0]));
        }
        let shape: [u8; 4] = match count {
            2 => [1, 1, 0, 0],
            3 => [1, 2, 2, 0],
            _ => match reader.read(1)? {
                0 => [2, 2, 2, 2],
                _ => [1, 2, 3, 3],
            },
        };
        let mut lengths = vec![0u8; alphabet];
        for (index, symbol) in symbols.iter().enumerate() {
            lengths[*symbol] = shape[index];
        }
        Ok(Self::Tree(HuffmanTree::from_lengths(&lengths)?))
    }

    /// The code the lengths of a complex description name, skipping `skip` of the length codes.
    pub fn complex(reader: &mut BrotliReader<'_>, alphabet: usize, skip: usize) -> Result<Self, BrotliError> {
        let fixed = HuffmanTree::from_lengths(&Brotli::FIXED)?;
        let mut order = [0u8; Brotli::CODES];
        let mut space = 32i32;
        let mut used = 0;
        for index in skip..Brotli::CODES {
            let length = Self::walk(reader, &fixed)? as u8;
            order[Brotli::ORDER[index]] = length;
            if length != 0 {
                space -= 32 >> length;
                used += 1;
                if space <= 0 {
                    break;
                }
            }
        }
        if used != 1 && space != 0 {
            return Err(BrotliError::Format);
        }
        let codes = match used {
            1 => Self::Single(order.iter().position(|length| *length > 0).ok_or(BrotliError::Format)?),
            _ => Self::Tree(HuffmanTree::from_lengths(&order)?),
        };
        Ok(Self::Tree(HuffmanTree::from_lengths(&Self::lengths(reader, alphabet, &codes)?)?))
    }

    /// The code lengths a complex description carries, one run of the code length alphabet at a time.
    pub fn lengths(reader: &mut BrotliReader<'_>, alphabet: usize, codes: &BrotliCode) -> Result<Vec<u8>, BrotliError> {
        let mut lengths = vec![0u8; alphabet];
        let mut symbol = 0;
        let mut previous = Brotli::REPEATED;
        let mut repeat = 0usize;
        let mut repeated = 0u8;
        let mut space = 32768i32;
        while symbol < alphabet && space > 0 {
            match codes.symbol(reader)? {
                length @ 0..=15 => {
                    repeat = 0;
                    lengths[symbol] = length as u8;
                    symbol += 1;
                    if length != 0 {
                        previous = length as u8;
                        space -= 32768 >> length;
                    }
                }
                code @ (16 | 17) => {
                    let (bits, length) = match code {
                        16 => (2u8, previous),
                        _ => (3, 0),
                    };
                    if repeated != length {
                        repeat = 0;
                        repeated = length;
                    }
                    let held = repeat;
                    if repeat > 0 {
                        repeat = (repeat - 2) << bits;
                    }
                    repeat += reader.read(bits)? as usize + 3;
                    let run = repeat - held;
                    if symbol + run > alphabet {
                        return Err(BrotliError::Format);
                    }
                    for _ in 0..run {
                        lengths[symbol] = repeated;
                        symbol += 1;
                    }
                    if repeated != 0 {
                        space -= (run as i32) << (15 - repeated);
                    }
                }
                _ => return Err(BrotliError::Format),
            }
        }
        match space == 0 {
            true => Ok(lengths),
            false => Err(BrotliError::Format),
        }
    }

    /// The symbol the stream names next.
    pub fn symbol(&self, reader: &mut BrotliReader<'_>) -> Result<usize, BrotliError> {
        match self {
            Self::Single(symbol) => Ok(*symbol),
            Self::Tree(tree) => Self::walk(reader, tree),
        }
    }

    /// Walks `tree` one bit at a time, as the format writes its codes.
    pub fn walk(reader: &mut BrotliReader<'_>, tree: &HuffmanTree) -> Result<usize, BrotliError> {
        tree.walk(|| reader.bit().map(|bit| bit as u16))?.ok_or(BrotliError::Format)
    }

    /// The code the symbol frequencies of one alphabet ask for.
    pub fn from_frequencies(frequencies: &[u32]) -> Result<Self, BrotliError> {
        let mut frequencies = frequencies.to_vec();
        Brotli::pad(&mut frequencies);
        Ok(Self::Tree(HuffmanTree::from_frequencies(&frequencies, Brotli::MAXIMUM_LENGTH)?))
    }

    /// The tree this code names, which a single symbol carries none of.
    pub fn tree(&self) -> Option<&HuffmanTree> {
        match self {
            Self::Tree(tree) => Some(tree),
            Self::Single(_) => None,
        }
    }

    /// Writes this code as a complex description, which `read` takes back.
    pub fn write(&self, writer: &mut BrotliWriter) -> Result<(), BrotliError> {
        let tree = self.tree().ok_or(BrotliError::Format)?;
        let count = tree.lengths().iter().rposition(|length| *length > 0).map_or(0, |index| index + 1);
        let runs = Brotli::runs(&tree.lengths()[..count]);
        let mut frequencies = vec![0u32; Brotli::CODES];
        for (symbol, _, _) in runs.iter() {
            frequencies[*symbol] += 1;
        }
        Brotli::pad(&mut frequencies);
        let codes = HuffmanTree::from_frequencies(&frequencies, Brotli::MAXIMUM_CODE)?;
        let named = (0..Brotli::CODES).rposition(|index| codes.lengths()[Brotli::ORDER[index]] > 0).map_or(0, |index| index + 1);
        let fixed = HuffmanTree::from_lengths(&Brotli::FIXED)?;
        writer.write(0, 2);
        for index in 0..named {
            let (code, length) = fixed.encode(codes.lengths()[Brotli::ORDER[index]] as usize).ok_or(BrotliError::Format)?;
            writer.code(code, length);
        }
        for (symbol, extra, bits) in runs.iter() {
            let (code, length) = codes.encode(*symbol).ok_or(BrotliError::Format)?;
            writer.code(code, length);
            writer.write(*extra as u64, *bits);
        }
        Ok(())
    }

    /// Writes one symbol through this code.
    pub fn encode(&self, writer: &mut BrotliWriter, symbol: usize) -> Result<(), BrotliError> {
        match self {
            Self::Single(named) => match *named == symbol {
                true => Ok(()),
                false => Err(BrotliError::Format),
            },
            Self::Tree(tree) => {
                let (code, length) = tree.encode(symbol).ok_or(BrotliError::Format)?;
                writer.code(code, length);
                Ok(())
            }
        }
    }
}

/// The four distances a meta-block may name again instead of writing one out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BrotliDistances {
    pub storage: [usize; 4],
    pub index: usize,
}

impl BrotliDistances {
    pub fn new() -> Self {
        Self { storage: Brotli::DISTANCES, index: 0 }
    }

    /// The distance `back` steps before the newest one, counting the newest as one.
    pub fn at(&self, back: usize) -> usize {
        self.storage[(self.index + 4 - back) % 4]
    }

    pub fn push(&mut self, distance: usize) {
        self.storage[self.index % 4] = distance;
        self.index += 1;
    }

    /// The distance one of the sixteen short codes names.
    pub fn short(&self, code: usize) -> Result<usize, BrotliError> {
        let (back, step) = match code {
            0 => (1, 0i64),
            1 => (2, 0),
            2 => (3, 0),
            3 => (4, 0),
            code @ 4..=9 => (1, [-1i64, 1, -2, 2, -3, 3][code - 4]),
            code @ 10..=15 => (2, [-1i64, 1, -2, 2, -3, 3][code - 10]),
            _ => return Err(BrotliError::Format),
        };
        let distance = self.at(back) as i64 + step;
        match distance > 0 {
            true => Ok(distance as usize),
            false => Err(BrotliError::Format),
        }
    }
}

impl Default for BrotliDistances {
    fn default() -> Self {
        Self::new()
    }
}

/// The block types one category switches between, and the run the current one still has left.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrotliSwitch {
    pub types: usize,
    pub kinds: Option<BrotliCode>,
    pub lengths: Option<BrotliCode>,
    pub current: usize,
    pub previous: usize,
    pub remaining: usize,
}

impl BrotliSwitch {
    /// The switch one block type needs nothing written for.
    pub fn single() -> Self {
        Self { types: 1, kinds: None, lengths: None, current: 0, previous: 1, remaining: usize::MAX }
    }

    /// The switch a meta-block header names.
    pub fn read(reader: &mut BrotliReader<'_>) -> Result<Self, BrotliError> {
        let types = Brotli::count(reader)?;
        if types == 1 {
            return Ok(Self::single());
        }
        let kinds = BrotliCode::read(reader, types + 2)?;
        let lengths = BrotliCode::read(reader, Brotli::BLOCKS)?;
        let remaining = Brotli::length(reader, &lengths)?;
        Ok(Self { types, kinds: Some(kinds), lengths: Some(lengths), current: 0, previous: 1, remaining })
    }

    /// Writes the switch a meta-block header names.
    pub fn write(&self, writer: &mut BrotliWriter) -> Result<(), BrotliError> {
        Brotli::write_count(writer, self.types);
        if self.types == 1 {
            return Ok(());
        }
        let kinds = self.kinds.as_ref().ok_or(BrotliError::Format)?;
        let lengths = self.lengths.as_ref().ok_or(BrotliError::Format)?;
        kinds.write(writer)?;
        lengths.write(writer)?;
        Brotli::write_length(writer, lengths, self.remaining)
    }

    /// Takes one symbol out of the current run, switching to another type when the run ends.
    pub fn step(&mut self, reader: &mut BrotliReader<'_>) -> Result<usize, BrotliError> {
        if self.remaining == 0 {
            let (symbol, run) = match (&self.kinds, &self.lengths) {
                (Some(kinds), Some(lengths)) => (kinds.symbol(reader)?, Brotli::length(reader, lengths)?),
                _ => return Err(BrotliError::Format),
            };
            let next = match symbol {
                0 => self.previous,
                1 => (self.current + 1) % self.types,
                symbol => symbol - 2,
            };
            if next >= self.types {
                return Err(BrotliError::Format);
            }
            self.previous = self.current;
            self.current = next;
            self.remaining = run;
        }
        self.remaining -= 1;
        Ok(self.current)
    }
}

/// The header one prefix coded meta-block opens with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrotliMeta {
    pub literals: BrotliSwitch,
    pub commands: BrotliSwitch,
    pub distances: BrotliSwitch,
    pub postfix: u8,
    pub direct: usize,
    pub contexts: Vec<BrotliContext>,
    pub literal_map: Vec<u8>,
    pub distance_map: Vec<u8>,
    pub literal_codes: Vec<BrotliCode>,
    pub command_codes: Vec<BrotliCode>,
    pub distance_codes: Vec<BrotliCode>,
}

impl BrotliMeta {
    /// The number of distance codes a meta-block names, which its postfix and direct bits set.
    pub fn alphabet(&self) -> usize {
        Brotli::SHORT + self.direct + (48 << self.postfix)
    }

    /// The header the stream carries.
    pub fn read(reader: &mut BrotliReader<'_>) -> Result<Self, BrotliError> {
        let literals = BrotliSwitch::read(reader)?;
        let commands = BrotliSwitch::read(reader)?;
        let distances = BrotliSwitch::read(reader)?;
        let postfix = reader.read(2)? as u8;
        let direct = (reader.read(4)? as usize) << postfix;
        let mut contexts = Vec::with_capacity(literals.types);
        for _ in 0..literals.types {
            contexts.push(BrotliContext::from_bits(reader.read(2)?)?);
        }
        let trees = Brotli::count(reader)?;
        let literal_map = Self::map(reader, BrotliContext::CONTEXTS * literals.types, trees)?;
        let named = Brotli::count(reader)?;
        let distance_map = Self::map(reader, Brotli::DISTANCE_CONTEXTS * distances.types, named)?;
        let mut meta = Self {
            literals,
            commands,
            distances,
            postfix,
            direct,
            contexts,
            literal_map,
            distance_map,
            literal_codes: Vec::new(),
            command_codes: Vec::new(),
            distance_codes: Vec::new(),
        };
        for _ in 0..trees {
            meta.literal_codes.push(BrotliCode::read(reader, Brotli::LITERALS)?);
        }
        for _ in 0..meta.commands.types {
            meta.command_codes.push(BrotliCode::read(reader, Brotli::COMMANDS)?);
        }
        let alphabet = meta.alphabet();
        for _ in 0..named {
            meta.distance_codes.push(BrotliCode::read(reader, alphabet)?);
        }
        Ok(meta)
    }

    /// Writes the header this meta-block opens with, which `read` takes back.
    pub fn write(&self, writer: &mut BrotliWriter) -> Result<(), BrotliError> {
        self.literals.write(writer)?;
        self.commands.write(writer)?;
        self.distances.write(writer)?;
        writer.write(self.postfix as u64, 2);
        writer.write((self.direct >> self.postfix) as u64, 4);
        for context in self.contexts.iter() {
            writer.write(context.bits(), 2);
        }
        Brotli::write_count(writer, self.literal_codes.len());
        Self::write_map(writer, &self.literal_map, self.literal_codes.len())?;
        Brotli::write_count(writer, self.distance_codes.len());
        Self::write_map(writer, &self.distance_map, self.distance_codes.len())?;
        for code in self.literal_codes.iter().chain(self.command_codes.iter()).chain(self.distance_codes.iter()) {
            code.write(writer)?;
        }
        Ok(())
    }

    /// The context map one category carries, which names the tree every context reads through.
    pub fn map(reader: &mut BrotliReader<'_>, size: usize, trees: usize) -> Result<Vec<u8>, BrotliError> {
        if trees == 0 {
            return Err(BrotliError::Format);
        }
        if trees == 1 {
            return Ok(vec![0; size]);
        }
        let runs = match reader.read(1)? {
            0 => 0,
            _ => reader.read(4)? as usize + 1,
        };
        let code = BrotliCode::read(reader, runs + trees)?;
        let mut map = Vec::with_capacity(size);
        while map.len() < size {
            let symbol = code.symbol(reader)?;
            match symbol {
                0 => map.push(0),
                symbol if symbol <= runs => {
                    let count = (1usize << symbol) + reader.read(symbol as u8)? as usize;
                    if map.len() + count > size {
                        return Err(BrotliError::Format);
                    }
                    map.resize(map.len() + count, 0);
                }
                symbol => map.push((symbol - runs) as u8),
            }
        }
        if reader.read(1)? == 1 {
            Self::unshuffle(&mut map);
        }
        match map.iter().all(|tree| (*tree as usize) < trees) {
            true => Ok(map),
            false => Err(BrotliError::Format),
        }
    }

    /// Writes a context map, which one tree needs nothing written for.
    pub fn write_map(writer: &mut BrotliWriter, map: &[u8], trees: usize) -> Result<(), BrotliError> {
        if trees == 1 {
            return Ok(());
        }
        writer.write(0, 1);
        let mut frequencies = vec![0u32; trees];
        for tree in map {
            frequencies[*tree as usize] += 1;
        }
        let code = BrotliCode::from_frequencies(&frequencies)?;
        code.write(writer)?;
        for tree in map {
            code.encode(writer, *tree as usize)?;
        }
        writer.write(0, 1);
        Ok(())
    }

    /// Moves every value of a context map back to the front, which is how it was written.
    pub fn unshuffle(map: &mut [u8]) {
        let mut order: Vec<u8> = (0..=255).collect();
        for entry in map.iter_mut() {
            let index = *entry as usize;
            let value = order[index];
            order.copy_within(0..index, 1);
            order[0] = value;
            *entry = value;
        }
    }

    /// The tree one literal reads through, which its block type and context name.
    pub fn literal(&self, block: usize, context: usize) -> Result<&BrotliCode, BrotliError> {
        let index = *self.literal_map.get(block * BrotliContext::CONTEXTS + context).ok_or(BrotliError::Format)?;
        self.literal_codes.get(index as usize).ok_or(BrotliError::Format)
    }

    /// The tree one distance reads through, which its block type and context name.
    pub fn distance(&self, block: usize, context: usize) -> Result<&BrotliCode, BrotliError> {
        let index = *self.distance_map.get(block * Brotli::DISTANCE_CONTEXTS + context).ok_or(BrotliError::Format)?;
        self.distance_codes.get(index as usize).ok_or(BrotliError::Format)
    }

    /// The distance one code names, out of the bits that follow it.
    ///
    /// The codes right past the ones that name an earlier distance stand for a distance each,
    /// as many of them as the header names; every code past those carries bits of its own.
    pub fn offset(&self, reader: &mut BrotliReader<'_>, code: usize) -> Result<usize, BrotliError> {
        if code < Brotli::SHORT || code >= self.alphabet() {
            return Err(BrotliError::Format);
        }
        if code < Brotli::SHORT + self.direct {
            return Ok(code - Brotli::SHORT + 1);
        }
        let value = code - Brotli::SHORT - self.direct;
        let bits = 1 + (value >> (self.postfix + 1)) as u8;
        let high = value >> self.postfix;
        let low = value & ((1usize << self.postfix) - 1);
        let extra = reader.read(bits)? as usize;
        let base = ((2 + (high & 1)) << bits) - 4;
        Ok(((base + extra) << self.postfix) + low + self.direct + 1)
    }

    /// The code and extra bits a distance is written as, which `offset` reads back.
    pub fn code(&self, distance: usize) -> Option<(usize, u64, u8)> {
        if distance <= self.direct {
            return Some((Brotli::SHORT + distance - 1, 0, 0));
        }
        for code in Brotli::SHORT + self.direct..self.alphabet() {
            let value = code - Brotli::SHORT - self.direct;
            let bits = 1 + (value >> (self.postfix + 1)) as u8;
            let high = value >> self.postfix;
            let low = value & ((1usize << self.postfix) - 1);
            let base = ((2 + (high & 1)) << bits) - 4;
            let start = (base << self.postfix) + low + self.direct + 1;
            let extra = distance.wrapping_sub(start) >> self.postfix;
            if distance >= start && extra < 1usize << bits && (extra << self.postfix) + start == distance {
                return Some((code, extra as u64, bits));
            }
        }
        None
    }
}

/// One command of a meta-block: a run of literals, then a copy of an earlier run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BrotliCommand {
    pub literals: usize,
    pub distance: usize,
    pub copy: usize,
}

impl BrotliCommand {
    /// The insert-and-copy symbol this command is written as, and the two codes it holds.
    pub fn codes(&self) -> Result<(usize, usize, usize), BrotliError> {
        let insert = Brotli::INSERTS.partition_point(|(base, _)| *base as usize <= self.literals).checked_sub(1).ok_or(BrotliError::Format)?;
        let copy = Brotli::COPIES.partition_point(|(base, _)| *base as usize <= self.copy).checked_sub(1).ok_or(BrotliError::Format)?;
        Ok((Brotli::commanded(insert, copy)?, insert, copy))
    }
}

impl Brotli {
    /// The smallest and largest window the format names.
    pub const MINIMUM_WINDOW: u8 = 10;
    pub const MAXIMUM_WINDOW: u8 = 24;
    /// The bytes the window holds back from the size it names.
    pub const SLACK: usize = 16;
    /// The most content one meta-block carries.
    pub const META_BLOCK: usize = 1 << 24;
    /// The longest code a prefix code may carry, and the longest one its lengths are written under.
    pub const MAXIMUM_LENGTH: u8 = 15;
    pub const MAXIMUM_CODE: u8 = 5;
    /// The number of code length symbols a complex description names.
    pub const CODES: usize = 18;
    /// The order the code length alphabet is written in.
    pub const ORDER: [usize; 18] = [1, 2, 3, 4, 0, 5, 17, 6, 16, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    /// The fixed code the lengths of the code length alphabet are written under.
    pub const FIXED: [u8; 6] = [2, 4, 3, 2, 2, 4];
    /// The code length a repeat starts out copying.
    pub const REPEATED: u8 = 8;
    /// The number of literal symbols.
    pub const LITERALS: usize = 256;
    /// The number of insert-and-copy symbols.
    pub const COMMANDS: usize = 704;
    /// The number of distance codes that name an earlier distance.
    pub const SHORT: usize = 16;
    /// The number of contexts every distance block type spreads its trees over.
    pub const DISTANCE_CONTEXTS: usize = 4;
    /// The number of block length symbols.
    pub const BLOCKS: usize = 26;
    /// The shortest and longest run a match may cover.
    pub const MINIMUM_COPY: usize = 2;
    pub const MAXIMUM_COPY: usize = 1 << 14;
    /// The shortest run the builtin codec writes a copy for.
    pub const MINIMUM_MATCH: usize = 4;
    /// The distances a stream opens with.
    pub const DISTANCES: [usize; 4] = [16, 15, 11, 4];
    /// The base and extra bits of every block length symbol.
    pub const BLOCK_LENGTHS: [(u32, u8); 26] = [
        (1, 2), (5, 2), (9, 2), (13, 2), (17, 3), (25, 3), (33, 3), (41, 3),
        (49, 4), (65, 4), (81, 4), (97, 4), (113, 5), (145, 5), (177, 5), (209, 5),
        (241, 6), (305, 6), (369, 7), (497, 8), (753, 9), (1265, 10), (2289, 11), (4337, 12),
        (8433, 13), (16625, 24),
    ];
    /// The base and extra bits of every insert length symbol.
    pub const INSERTS: [(u32, u8); 24] = [
        (0, 0), (1, 0), (2, 0), (3, 0), (4, 0), (5, 0), (6, 1), (8, 1),
        (10, 2), (14, 2), (18, 3), (26, 3), (34, 4), (50, 4), (66, 5), (98, 5),
        (130, 6), (194, 7), (322, 8), (578, 9), (1090, 10), (2114, 12), (6210, 14), (22594, 24),
    ];
    /// The base and extra bits of every copy length symbol.
    pub const COPIES: [(u32, u8); 24] = [
        (2, 0), (3, 0), (4, 0), (5, 0), (6, 0), (7, 0), (8, 0), (9, 0),
        (10, 1), (12, 1), (14, 2), (18, 2), (22, 3), (30, 3), (38, 4), (54, 4),
        (70, 5), (102, 5), (134, 6), (198, 7), (326, 8), (582, 9), (1094, 10), (2118, 24),
    ];
    /// The insert and copy code every range of the insert-and-copy alphabet opens at.
    pub const INSERT_RANGES: [usize; 9] = [0, 0, 8, 8, 0, 16, 8, 16, 16];
    pub const COPY_RANGES: [usize; 9] = [0, 8, 0, 8, 16, 0, 16, 8, 16];

    /// The window this codec asks for, held inside the range the format names.
    pub fn window(&self) -> u8 {
        self.window.clamp(Self::MINIMUM_WINDOW, Self::MAXIMUM_WINDOW)
    }

    /// The widest distance a match may reach back, which the window sets.
    pub fn backward(window: u8) -> usize {
        (1usize << window) - Self::SLACK
    }

    /// The number of earlier positions one match search walks, which the quality sets.
    pub fn probes(&self) -> usize {
        match self.quality {
            0..=3 => 8,
            4..=7 => 32,
            8..=10 => 128,
            _ => 512,
        }
    }

    /// The bits the index of a symbol out of `alphabet` of them spends.
    pub fn width(alphabet: usize) -> u8 {
        (usize::BITS - alphabet.saturating_sub(1).leading_zeros()) as u8
    }

    /// Counts two symbols at the least, which is what holds a code complete.
    pub fn pad(frequencies: &mut [u32]) {
        if frequencies.iter().filter(|frequency| **frequency > 0).count() >= 2 {
            return;
        }
        for frequency in frequencies.iter_mut().take(2) {
            *frequency = (*frequency).max(1);
        }
    }

    /// Writes the window size that opens a stream.
    pub fn header(writer: &mut BrotliWriter, window: u8) {
        match window {
            16 => writer.write(0, 1),
            17 => writer.write(0b0000001, 7),
            18..=24 => writer.write(1 | ((window as u64 - 17) << 1), 4),
            _ => writer.write(0b0000001 | ((window as u64 - 8) << 4), 7),
        }
    }

    /// The window size a stream opens with.
    pub fn window_of(reader: &mut BrotliReader<'_>) -> Result<u8, BrotliError> {
        if reader.read(1)? == 0 {
            return Ok(16);
        }
        let value = reader.read(3)?;
        if value != 0 {
            return Ok(17 + value as u8);
        }
        match reader.read(3)? {
            0 => Ok(17),
            1 => Err(BrotliError::Format),
            value => Ok(8 + value as u8),
        }
    }

    /// The number of block types or trees a header names, which one bit stands for one of.
    pub fn count(reader: &mut BrotliReader<'_>) -> Result<usize, BrotliError> {
        if reader.read(1)? == 0 {
            return Ok(1);
        }
        let bits = reader.read(3)? as u8;
        Ok((1usize << bits) + 1 + reader.read(bits)? as usize)
    }

    /// Writes a number of block types or trees.
    pub fn write_count(writer: &mut BrotliWriter, count: usize) {
        if count == 1 {
            writer.write(0, 1);
            return;
        }
        let bits = (usize::BITS - 1 - (count - 1).leading_zeros()) as u8;
        writer.write(1, 1);
        writer.write(bits as u64, 3);
        writer.write((count - 1 - (1usize << bits)) as u64, bits);
    }

    /// The block length one symbol names, out of the bits that follow it.
    pub fn length(reader: &mut BrotliReader<'_>, code: &BrotliCode) -> Result<usize, BrotliError> {
        let symbol = code.symbol(reader)?;
        let (base, bits) = *Self::BLOCK_LENGTHS.get(symbol).ok_or(BrotliError::Format)?;
        Ok(base as usize + reader.read(bits)? as usize)
    }

    /// Writes a block length.
    pub fn write_length(writer: &mut BrotliWriter, code: &BrotliCode, length: usize) -> Result<(), BrotliError> {
        let symbol = Self::BLOCK_LENGTHS.iter().rposition(|(base, _)| *base as usize <= length).ok_or(BrotliError::Format)?;
        let (base, bits) = Self::BLOCK_LENGTHS[symbol];
        code.encode(writer, symbol)?;
        writer.write((length - base as usize) as u64, bits);
        Ok(())
    }

    /// The insert code, the copy code and whether a distance follows one insert-and-copy symbol.
    pub fn command(code: usize) -> Result<(usize, usize, bool), BrotliError> {
        if code >= Self::COMMANDS {
            return Err(BrotliError::Format);
        }
        let (range, named) = match code >> 6 {
            range @ 2.. => (range - 2, true),
            range => (range, false),
        };
        Ok((Self::INSERT_RANGES[range] + ((code >> 3) & 7), Self::COPY_RANGES[range] + (code & 7), named))
    }

    /// The insert-and-copy symbol one pair of codes is written as, with a distance of its own.
    pub fn commanded(insert: usize, copy: usize) -> Result<usize, BrotliError> {
        let range = (0..9).find(|range| Self::INSERT_RANGES[*range] == insert & !7 && Self::COPY_RANGES[*range] == copy & !7).ok_or(BrotliError::Format)?;
        Ok((range + 2) * 64 + ((insert & 7) << 3) + (copy & 7))
    }

    /// The runs the code length alphabet writes `lengths` as, which `lengths` reads back.
    ///
    /// Only a run of zeros travels through a repeat code, which keeps the count the reader carries
    /// out of every length that follows one.
    pub fn runs(lengths: &[u8]) -> Vec<(usize, u32, u8)> {
        let mut runs = Vec::new();
        let mut index = 0;
        while index < lengths.len() {
            if lengths[index] != 0 {
                runs.push((lengths[index] as usize, 0, 0));
                index += 1;
                continue;
            }
            let mut count = lengths[index..].iter().take_while(|length| **length == 0).count();
            index += count;
            let mut repeat = 0usize;
            while count > 0 {
                let base = match repeat {
                    0 => 0,
                    repeat => (repeat - 2) << 3,
                };
                match count < 3 || base + 3 > repeat + count {
                    true => {
                        runs.push((0, 0, 0));
                        count -= 1;
                        repeat = 0;
                    }
                    false => {
                        let extra = (count + repeat - base - 3).min(7);
                        let next = base + 3 + extra;
                        runs.push((17, extra as u32, 3));
                        count -= next - repeat;
                        repeat = next;
                    }
                }
            }
        }
        runs
    }
}

impl Brotli {
    /// Encodes `data` as a stream of meta-blocks, which is what the builtin codec writes.
    pub fn encode(&self, data: &[u8]) -> Result<Vec<u8>, BrotliError> {
        let window = self.window();
        let mut writer = BrotliWriter::new();
        Self::header(&mut writer, window);
        let mut matcher = LZ77Matcher::new(Self::backward(window), Self::MAXIMUM_COPY, data.len()).with_probes(self.probes());
        for start in (0..data.len()).step_by(Self::META_BLOCK) {
            let end = (start + Self::META_BLOCK).min(data.len());
            let commands = self.commands(data, start, end, &mut matcher);
            let mark = writer.mark();
            let stored = Self::stored_length(&writer, end - start);
            match self.deflate(&mut writer, data, start, end, &commands) {
                Ok(()) if writer.length() < stored => {}
                _ => {
                    writer.rewind(mark);
                    Self::store(&mut writer, &data[start..end]);
                }
            }
        }
        writer.write(1, 1);
        writer.write(1, 1);
        Ok(writer.finish())
    }

    /// Writes one uncompressed meta-block, which every shape of content fits in.
    pub fn store(writer: &mut BrotliWriter, block: &[u8]) {
        writer.write(0, 1);
        writer.write(Self::nibbles(block.len()) as u64 - 4, 2);
        writer.write(block.len() as u64 - 1, Self::nibbles(block.len()) * 4);
        writer.write(1, 1);
        writer.bytes(block);
    }

    /// The bits `store` would leave the stream at, which every compressed shape is measured against.
    pub fn stored_length(writer: &BrotliWriter, length: usize) -> usize {
        (writer.length() + 4 + Self::nibbles(length) as usize * 4).div_ceil(8) * 8 + length * 8
    }

    /// The nibbles the length of one meta-block spends, which never carries nothing.
    pub fn nibbles(length: usize) -> u8 {
        match length.saturating_sub(1) {
            0..=0xFFFF => 4,
            0x1_0000..=0xF_FFFF => 5,
            _ => 6,
        }
    }

    /// The commands LZ77 matching finds in one meta-block of `data`.
    pub fn commands(&self, data: &[u8], start: usize, end: usize, matcher: &mut LZ77Matcher) -> Vec<BrotliCommand> {
        let mut commands = Vec::new();
        let mut run = 0;
        let mut offset = start;
        while offset < end {
            match matcher.find(data, offset, Self::MINIMUM_MATCH, end - offset) {
                Some((distance, copy)) => {
                    commands.push(BrotliCommand { literals: run, distance, copy });
                    run = 0;
                    for step in 0..copy {
                        matcher.insert(data, offset + step);
                    }
                    offset += copy;
                }
                None => {
                    run += 1;
                    matcher.insert(data, offset);
                    offset += 1;
                }
            }
        }
        if run > 0 {
            commands.push(BrotliCommand { literals: run, distance: 0, copy: Self::MINIMUM_COPY });
        }
        commands
    }

    /// Writes one prefix coded meta-block, which carries the commands of one run of `data`.
    pub fn deflate(&self, writer: &mut BrotliWriter, data: &[u8], start: usize, end: usize, commands: &[BrotliCommand]) -> Result<(), BrotliError> {
        if commands.is_empty() {
            return Err(BrotliError::Format);
        }
        let meta = self.meta(data, start, commands)?;
        let length = end - start;
        writer.write(0, 1);
        writer.write(Self::nibbles(length) as u64 - 4, 2);
        writer.write(length as u64 - 1, Self::nibbles(length) * 4);
        writer.write(0, 1);
        meta.write(writer)?;
        let mut offset = start;
        for command in commands {
            let (symbol, insert, copy) = command.codes()?;
            meta.command_codes.first().ok_or(BrotliError::Format)?.encode(writer, symbol)?;
            let (base, bits) = Self::INSERTS[insert];
            writer.write((command.literals - base as usize) as u64, bits);
            let (base, bits) = Self::COPIES[copy];
            writer.write((command.copy - base as usize) as u64, bits);
            for step in 0..command.literals {
                let context = meta.contexts[0].id(Self::before(data, offset + step, 1), Self::before(data, offset + step, 2));
                meta.literal(0, context)?.encode(writer, data[offset + step] as usize)?;
            }
            offset += command.literals;
            if command.distance == 0 {
                break;
            }
            let (code, extra, bits) = meta.code(command.distance).ok_or(BrotliError::Format)?;
            meta.distance(0, copy.min(3))?.encode(writer, code)?;
            writer.write(extra, bits);
            offset += command.copy;
        }
        match offset == end {
            true => Ok(()),
            false => Err(BrotliError::Format),
        }
    }

    /// The byte `back` places before `offset`, which the start of a stream reads as zero.
    pub fn before(data: &[u8], offset: usize, back: usize) -> u8 {
        match offset.checked_sub(back) {
            Some(index) => data[index],
            None => 0,
        }
    }

    /// The header the commands of one meta-block ask for, which one block type of each holds.
    pub fn meta(&self, data: &[u8], start: usize, commands: &[BrotliCommand]) -> Result<BrotliMeta, BrotliError> {
        let mut meta = BrotliMeta {
            literals: BrotliSwitch::single(),
            commands: BrotliSwitch::single(),
            distances: BrotliSwitch::single(),
            postfix: 0,
            direct: 0,
            contexts: [BrotliContext::UTF8].to_vec(),
            literal_map: vec![0; BrotliContext::CONTEXTS],
            distance_map: vec![0; Self::DISTANCE_CONTEXTS],
            literal_codes: Vec::new(),
            command_codes: Vec::new(),
            distance_codes: Vec::new(),
        };
        let mut literals = vec![0u32; Self::LITERALS];
        let mut named = vec![0u32; Self::COMMANDS];
        let mut offsets = vec![0u32; meta.alphabet()];
        let mut offset = start;
        for command in commands {
            let (symbol, _, copy) = command.codes()?;
            named[symbol] += 1;
            for step in 0..command.literals {
                literals[data[offset + step] as usize] += 1;
            }
            offset += command.literals;
            if command.distance == 0 {
                break;
            }
            let (code, _, _) = meta.code(command.distance).ok_or(BrotliError::Format)?;
            *offsets.get_mut(code).ok_or(BrotliError::Format)? += 1;
            offset += command.copy;
            let _ = copy;
        }
        meta.literal_codes.push(BrotliCode::from_frequencies(&literals)?);
        meta.command_codes.push(BrotliCode::from_frequencies(&named)?);
        meta.distance_codes.push(BrotliCode::from_frequencies(&offsets)?);
        Ok(meta)
    }

    /// Decodes a stream of meta-blocks, which is what the builtin codec reads.
    pub fn decode(&self, data: &[u8]) -> Result<Vec<u8>, BrotliError> {
        let mut reader = BrotliReader::new(data);
        let window = Self::window_of(&mut reader)?;
        let mut output = Vec::new();
        let mut distances = BrotliDistances::new();
        loop {
            let last = reader.read(1)? == 1;
            if last && reader.read(1)? == 1 {
                return Ok(output);
            }
            let nibbles = reader.read(2)?;
            if nibbles == 3 {
                if last || reader.read(1)? != 0 {
                    return Err(BrotliError::Format);
                }
                let bytes = reader.read(2)? as u8;
                match bytes {
                    0 => reader.align(),
                    _ => {
                        let length = reader.read(bytes * 8)? as usize + 1;
                        reader.take(length)?;
                        0
                    }
                };
                continue;
            }
            let nibbles = nibbles as u8 + 4;
            let length = reader.read(nibbles * 4)? as usize + 1;
            let uncompressed = match last {
                true => false,
                false => reader.read(1)? == 1,
            };
            if self.limit.is_some_and(|limit| output.len() + length > limit) {
                return Err(BrotliError::Limit);
            }
            match uncompressed {
                true => output.extend_from_slice(reader.take(length)?),
                false => self.inflate(&mut reader, &mut output, length, window, &mut distances)?,
            }
            if last {
                return Ok(output);
            }
        }
    }

    /// Reads the commands of one prefix coded meta-block into `output`.
    pub fn inflate(&self, reader: &mut BrotliReader<'_>, output: &mut Vec<u8>, length: usize, window: u8, distances: &mut BrotliDistances) -> Result<(), BrotliError> {
        let mut meta = BrotliMeta::read(reader)?;
        let backward = Self::backward(window);
        let mut remaining = length as i64;
        while remaining > 0 {
            let block = meta.commands.step(reader)?;
            let symbol = meta.command_codes.get(block).ok_or(BrotliError::Format)?.symbol(reader)?;
            let (insert, copy, named) = Self::command(symbol)?;
            let (base, bits) = Self::INSERTS[insert];
            let inserted = base as usize + reader.read(bits)? as usize;
            let (base, bits) = Self::COPIES[copy];
            let copied = base as usize + reader.read(bits)? as usize;
            if inserted as i64 > remaining {
                return Err(BrotliError::Format);
            }
            if self.limit.is_some_and(|limit| output.len() + inserted > limit) {
                return Err(BrotliError::Limit);
            }
            for _ in 0..inserted {
                let block = meta.literals.step(reader)?;
                let mode = *meta.contexts.get(block).ok_or(BrotliError::Format)?;
                let context = mode.id(Self::before(output, output.len(), 1), Self::before(output, output.len(), 2));
                let literal = meta.literal(block, context)?.symbol(reader)?;
                output.push(literal as u8);
            }
            remaining -= inserted as i64;
            if remaining <= 0 {
                break;
            }
            let (distance, push) = match named {
                true => {
                    let block = meta.distances.step(reader)?;
                    let code = meta.distance(block, copy.min(3))?.symbol(reader)?;
                    match code < Self::SHORT {
                        true => (distances.short(code)?, code != 0),
                        false => (meta.offset(reader, code)?, true),
                    }
                }
                false => (distances.at(1), false),
            };
            let maximum = backward.min(output.len());
            match distance > maximum {
                // A transform may hand back fewer bytes than the word it reads, so only the run
                // this meta-block still has left tells whether a dictionary word overruns it.
                true => remaining -= self.word(output, distance - maximum - 1, copied)? as i64,
                false => {
                    if distance == 0 || copied as i64 > remaining {
                        return Err(BrotliError::Format);
                    }
                    if push {
                        distances.push(distance);
                    }
                    if self.limit.is_some_and(|limit| output.len() + copied > limit) {
                        return Err(BrotliError::Limit);
                    }
                    let start = output.len() - distance;
                    for step in 0..copied {
                        output.push(output[start + step]);
                    }
                    remaining -= copied as i64;
                }
            }
        }
        match remaining == 0 {
            true => Ok(()),
            false => Err(BrotliError::Format),
        }
    }

    /// Copies the dictionary word a distance past the window names, and reports its length.
    pub fn word(&self, output: &mut Vec<u8>, named: usize, length: usize) -> Result<usize, BrotliError> {
        if !(BrotliDictionary::MINIMUM..=BrotliDictionary::MAXIMUM).contains(&length) {
            return Err(BrotliError::Format);
        }
        let count = BrotliDictionary::count(length);
        let word = BrotliDictionary::word(length, named % count).ok_or(BrotliError::Format)?;
        let transform = BrotliTransform::at(named / count).ok_or(BrotliError::Format)?;
        let bytes = transform.apply(word);
        if self.limit.is_some_and(|limit| output.len() + bytes.len() > limit) {
            return Err(BrotliError::Limit);
        }
        output.extend_from_slice(&bytes);
        Ok(bytes.len())
    }
}

#[derive(Debug)]
pub struct BrotliEncoder {
    options: Brotli,
    input: Vec<u8>,
    backend: ProviderBackend<dyn CodecProvider>,
}

impl BrotliEncoder {
    pub fn new(options: Brotli) -> Self {
        match CodecProviders::backend(&options.request(CodecDirection::Encode)) {
            ProviderBackend::Builtin => Self { options, input: Vec::new(), backend: ProviderBackend::Builtin },
            backend => Self { options, input: Vec::new(), backend },
        }
    }

    pub fn options(&self) -> &Brotli {
        &self.options
    }

    /// Holds `data` until the stream is finalized, which is when the builtin codec runs.
    pub fn update(&mut self, data: &[u8]) -> Result<Vec<u8>, BrotliError> {
        match &self.backend {
            ProviderBackend::Builtin => {
                self.input.extend_from_slice(data);
                Ok(Vec::new())
            }
            ProviderBackend::Handle { provider, handle } => Ok(provider.update(*handle, data)?),
        }
    }

    pub fn finalize(self) -> Result<Vec<u8>, BrotliError> {
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
pub struct BrotliDecoder {
    options: Brotli,
    input: Vec<u8>,
    backend: ProviderBackend<dyn CodecProvider>,
}

impl BrotliDecoder {
    pub fn new(options: Brotli) -> Self {
        match CodecProviders::backend(&options.request(CodecDirection::Decode)) {
            ProviderBackend::Builtin => Self { options, input: Vec::new(), backend: ProviderBackend::Builtin },
            backend => Self { options, input: Vec::new(), backend },
        }
    }

    pub fn options(&self) -> &Brotli {
        &self.options
    }

    /// Holds `data` until the stream is finalized, which is when the builtin codec runs.
    pub fn update(&mut self, data: &[u8]) -> Result<Vec<u8>, BrotliError> {
        match &self.backend {
            ProviderBackend::Builtin => {
                self.input.extend_from_slice(data);
                Ok(Vec::new())
            }
            ProviderBackend::Handle { provider, handle } => Ok(provider.update(*handle, data)?),
        }
    }

    pub fn finalize(self) -> Result<Vec<u8>, BrotliError> {
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

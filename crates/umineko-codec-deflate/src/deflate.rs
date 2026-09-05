use alloc::vec;
use alloc::vec::Vec;
use crate::errors::DeflateError;

use umineko_codec_huffman::HuffmanTree;
use umineko_codec_lz77::LZ77Matcher;

use umineko_helpers::provider::{CodecDirection, CodecProvider, CodecProviderRequest, CodecProviders, ProviderBackend};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deflate {
    pub level: u8,
    pub window: u8,
        pub limit: Option<usize>,
}

impl Default for Deflate {
    fn default() -> Self {
        Self {
            level: 6,
            window: 15,
            limit: None,
        }
    }
}

impl Deflate {
    pub const NAME: &'static str = "deflate";

    pub fn request(&self, direction: CodecDirection) -> CodecProviderRequest<'_> {
        CodecProviderRequest::new(Self::NAME, direction).with_level(self.level as i32).with_window(self.window).with_limit(self.limit)
    }

    pub fn encoder(&self) -> DeflateEncoder {
        DeflateEncoder::new(self.clone())
    }

    pub fn decoder(&self) -> DeflateDecoder {
        DeflateDecoder::new(self.clone())
    }

    pub fn compress(&self, data: &[u8]) -> Result<Vec<u8>, DeflateError> {
        match CodecProviders::transform(&self.request(CodecDirection::Encode), data)? {
            Some(output) => Ok(output),
            None => self.encode(data),
        }
    }

    pub fn decompress(&self, data: &[u8]) -> Result<Vec<u8>, DeflateError> {
        match CodecProviders::transform(&self.request(CodecDirection::Decode), data)? {
            Some(output) => Ok(output),
            None => self.decode(data),
        }
    }
}

/// Writes a DEFLATE bit stream, least significant bit first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeflateWriter {
    storage: Vec<u8>,
    holding: u32,
    held: u8,
}

impl DeflateWriter {
    pub fn new() -> Self {
        Self { storage: Vec::new(), holding: 0, held: 0 }
    }

    pub fn write(&mut self, bits: u32, length: u8) {
        if length == 0 {
            return;
        }
        self.holding |= (bits & (u32::MAX >> (32 - length))) << self.held;
        self.held += length;
        while self.held >= 8 {
            self.storage.push(self.holding as u8);
            self.holding >>= 8;
            self.held -= 8;
        }
    }

    /// Writes a Huffman code, whose bits travel most significant first.
    pub fn code(&mut self, code: u16, length: u8) {
        match length {
            0 => {}
            length => self.write((code.reverse_bits() >> (16 - length)) as u32, length),
        }
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

    pub fn len(&self) -> usize {
        self.storage.len()
    }

    pub fn is_empty(&self) -> bool {
        self.storage.is_empty() && self.held == 0
    }
}

impl Default for DeflateWriter {
    fn default() -> Self {
        Self::new()
    }
}

/// Reads a DEFLATE bit stream, least significant bit first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeflateReader<'a> {
    storage: &'a [u8],
    position: usize,
}

impl<'a> DeflateReader<'a> {
    pub fn new(storage: &'a [u8]) -> Self {
        Self { storage, position: 0 }
    }

    pub fn bit(&mut self) -> Result<u32, DeflateError> {
        let byte = self.storage.get(self.position / 8).ok_or(DeflateError::Truncated)?;
        let bit = (byte >> (self.position % 8)) & 1;
        self.position += 1;
        Ok(bit as u32)
    }

    pub fn bits(&mut self, length: u8) -> Result<u32, DeflateError> {
        let (mut value, mut filled) = (0u32, 0u8);
        while filled < length {
            let byte = *self.storage.get(self.position / 8).ok_or(DeflateError::Truncated)?;
            let used = (self.position % 8) as u8;
            let taken = (8 - used).min(length - filled);
            value |= (((byte >> used) as u32) & (u32::MAX >> (32 - taken))) << filled;
            self.position += taken as usize;
            filled += taken;
        }
        Ok(value)
    }

    /// Reads one symbol, following the canonical codes of `tree`.
    pub fn symbol(&mut self, tree: &HuffmanTree) -> Result<usize, DeflateError> {
        tree.walk(|| self.bit().map(|bit| bit as u16))?.ok_or(DeflateError::Format)
    }

    /// Drops the bits up to the next byte and returns that byte offset.
    pub fn align(&mut self) -> usize {
        self.position = self.position.div_ceil(8) * 8;
        self.position / 8
    }

    pub fn take(&mut self, length: usize) -> Result<&'a [u8], DeflateError> {
        let start = self.align();
        let end = start.checked_add(length).ok_or(DeflateError::Truncated)?;
        if end > self.storage.len() {
            return Err(DeflateError::Truncated);
        }
        self.position = end * 8;
        Ok(&self.storage[start..end])
    }

    pub fn position(&self) -> usize {
        self.position
    }
}

/// One token of a compressed block: a byte, or a copy of an earlier run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeflateToken {
    Literal(u8),
    Match { distance: u16, length: u16 },
}

/// The kind of block a stream carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeflateBlock {
    Stored,
    Fixed,
    Dynamic,
}

impl DeflateBlock {
    /// The two bits a block header names this kind with.
    pub fn bits(&self) -> u32 {
        match self {
            Self::Stored => 0,
            Self::Fixed => 1,
            Self::Dynamic => 2,
        }
    }

    /// The kind the two bits of a block header name.
    pub fn from_bits(bits: u32) -> Result<Self, DeflateError> {
        match bits {
            0 => Ok(Self::Stored),
            1 => Ok(Self::Fixed),
            2 => Ok(Self::Dynamic),
            _ => Err(DeflateError::Format),
        }
    }
}

/// One entry of the code length alphabet: a symbol, and the extra bits that follow it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeflateRun {
    pub symbol: usize,
    pub extra: u32,
    pub bits: u8,
}

/// The literal and distance codes one compressed block reads its symbols through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeflateCodes {
    pub literals: HuffmanTree,
    pub offsets: HuffmanTree,
}

impl DeflateCodes {
    /// The codes every fixed block carries.
    pub fn fixed() -> Result<Self, DeflateError> {
        Ok(Self { literals: Deflate::literals()?, offsets: Deflate::offsets()? })
    }

    /// The codes the symbols of `tokens` ask for.
    pub fn from_tokens(tokens: &[DeflateToken]) -> Result<Self, DeflateError> {
        let mut literals = vec![0u32; Deflate::LITERALS];
        let mut offsets = vec![0u32; Deflate::DISTANCES];
        for token in tokens {
            match token {
                DeflateToken::Literal(byte) => literals[*byte as usize] += 1,
                DeflateToken::Match { distance, length } => {
                    literals[Deflate::length(*length as usize).0] += 1;
                    offsets[Deflate::offset(*distance as usize).0] += 1;
                }
            }
        }
        literals[Deflate::END] += 1;
        Self::pad(&mut literals);
        Self::pad(&mut offsets);
        Ok(Self { literals: HuffmanTree::from_frequencies(&literals, Deflate::MAXIMUM_LENGTH)?, offsets: HuffmanTree::from_frequencies(&offsets, Deflate::MAXIMUM_LENGTH)? })
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

    /// Counts two code length symbols at the least, holding the spare one inside the written order.
    pub fn spare(frequencies: &mut [u32]) {
        if frequencies.iter().filter(|frequency| **frequency > 0).count() >= 2 {
            return;
        }
        if let Some(symbol) = Deflate::ORDER.iter().take(4).find(|symbol| frequencies[**symbol] == 0) {
            frequencies[*symbol] = 1;
        }
    }

    /// The number of code lengths a header writes, which never falls under `minimum`.
    pub fn count(lengths: &[u8], minimum: usize) -> usize {
        lengths.iter().rposition(|length| *length > 0).map_or(0, |index| index + 1).max(minimum)
    }

    /// The runs the code length alphabet writes `lengths` as.
    pub fn runs(lengths: &[u8]) -> Vec<DeflateRun> {
        let mut runs = Vec::new();
        let mut index = 0;
        while index < lengths.len() {
            let length = lengths[index];
            let mut repeat = lengths[index..].iter().take_while(|entry| **entry == length).count();
            index += repeat;
            if length != 0 {
                runs.push(DeflateRun { symbol: length as usize, extra: 0, bits: 0 });
                repeat -= 1;
            }
            while repeat >= 3 {
                let (symbol, taken, base, bits) = match length {
                    0 if repeat >= 11 => (18, repeat.min(138), 11, 7),
                    0 => (17, repeat.min(10), 3, 3),
                    _ => (16, repeat.min(6), 3, 2),
                };
                runs.push(DeflateRun { symbol, extra: (taken - base) as u32, bits });
                repeat -= taken;
            }
            for _ in 0..repeat {
                runs.push(DeflateRun { symbol: length as usize, extra: 0, bits: 0 });
            }
        }
        runs
    }

    /// The code lengths of both alphabets, trimmed to the counts a header names.
    pub fn lengths(&self) -> (Vec<u8>, usize, usize) {
        let literals = Self::count(self.literals.lengths(), 257);
        let offsets = Self::count(self.offsets.lengths(), 1);
        let mut lengths = self.literals.lengths()[..literals].to_vec();
        lengths.extend_from_slice(&self.offsets.lengths()[..offsets]);
        (lengths, literals, offsets)
    }

    /// Writes the code descriptions a dynamic block opens with.
    pub fn write(&self, writer: &mut DeflateWriter) -> Result<(), DeflateError> {
        let (lengths, literals, offsets) = self.lengths();
        let runs = Self::runs(&lengths);
        let mut frequencies = vec![0u32; Deflate::CODES];
        for run in runs.iter() {
            frequencies[run.symbol] += 1;
        }
        Self::spare(&mut frequencies);
        let tree = HuffmanTree::from_frequencies(&frequencies, Deflate::MAXIMUM_CODE)?;
        let codes = (0..Deflate::CODES).rposition(|index| tree.lengths()[Deflate::ORDER[index]] > 0).map_or(4, |index| index + 1).max(4);
        writer.write(literals as u32 - 257, 5);
        writer.write(offsets as u32 - 1, 5);
        writer.write(codes as u32 - 4, 4);
        for index in 0..codes {
            writer.write(tree.lengths()[Deflate::ORDER[index]] as u32, 3);
        }
        for run in runs.iter() {
            let (code, length) = tree.encode(run.symbol).ok_or(DeflateError::Format)?;
            writer.code(code, length);
            writer.write(run.extra, run.bits);
        }
        Ok(())
    }

    /// The codes a dynamic block carries.
    pub fn read(reader: &mut DeflateReader<'_>) -> Result<Self, DeflateError> {
        let literals = reader.bits(5)? as usize + 257;
        let offsets = reader.bits(5)? as usize + 1;
        let codes = reader.bits(4)? as usize + 4;
        let mut order = [0u8; Deflate::CODES];
        for index in 0..codes {
            order[Deflate::ORDER[index]] = reader.bits(3)? as u8;
        }
        let lengths = HuffmanTree::from_lengths(&order)?;
        let mut all = Vec::with_capacity(literals + offsets);
        while all.len() < literals + offsets {
            let (repeat, length) = match reader.symbol(&lengths)? {
                symbol @ 0..=15 => {
                    all.push(symbol as u8);
                    continue;
                }
                16 => (reader.bits(2)? as usize + 3, *all.last().ok_or(DeflateError::Format)?),
                17 => (reader.bits(3)? as usize + 3, 0),
                18 => (reader.bits(7)? as usize + 11, 0),
                _ => return Err(DeflateError::Format),
            };
            if all.len() + repeat > literals + offsets {
                return Err(DeflateError::Format);
            }
            all.resize(all.len() + repeat, length);
        }
        Ok(Self { literals: HuffmanTree::from_lengths(&all[..literals])?, offsets: HuffmanTree::from_lengths(&all[literals..])? })
    }
}

impl Deflate {
    /// The longest Huffman code the format allows.
    pub const MAXIMUM_LENGTH: u8 = 15;
    /// The symbol that closes a block.
    pub const END: usize = 256;
    /// The number of literal and length symbols.
    pub const SYMBOLS: usize = 288;
    /// The number of literal and length symbols a dynamic block may name.
    pub const LITERALS: usize = 286;
    /// The number of distance symbols.
    pub const DISTANCES: usize = 30;
    /// The number of code length symbols.
    pub const CODES: usize = 19;
    /// The longest code the code length alphabet may carry.
    pub const MAXIMUM_CODE: u8 = 7;
    /// The shortest and longest run a match may cover.
    pub const MINIMUM_MATCH: usize = 3;
    pub const MAXIMUM_MATCH: usize = 258;
    /// The most bytes one stored block carries.
    pub const STORED: usize = 65535;
    /// The base and extra bits of every length symbol, from symbol 257.
    pub const LENGTHS: [(u16, u8); 29] = [
        (3, 0), (4, 0), (5, 0), (6, 0), (7, 0), (8, 0), (9, 0), (10, 0),
        (11, 1), (13, 1), (15, 1), (17, 1), (19, 2), (23, 2), (27, 2), (31, 2),
        (35, 3), (43, 3), (51, 3), (59, 3), (67, 4), (83, 4), (99, 4), (115, 4),
        (131, 5), (163, 5), (195, 5), (227, 5), (258, 0),
    ];
    /// The base and extra bits of every distance symbol.
    pub const OFFSETS: [(u16, u8); 30] = [
        (1, 0), (2, 0), (3, 0), (4, 0), (5, 1), (7, 1), (9, 2), (13, 2),
        (17, 3), (25, 3), (33, 4), (49, 4), (65, 5), (97, 5), (129, 6), (193, 6),
        (257, 7), (385, 7), (513, 8), (769, 8), (1025, 9), (1537, 9), (2049, 10), (3073, 10),
        (4097, 11), (6145, 11), (8193, 12), (12289, 12), (16385, 13), (24577, 13),
    ];
    /// The order the code length alphabet is written in.
    pub const ORDER: [usize; 19] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

    /// The literal and length code every fixed block uses.
    pub fn literals() -> Result<HuffmanTree, DeflateError> {
        let mut lengths = [0u8; Self::SYMBOLS];
        for (symbol, length) in lengths.iter_mut().enumerate() {
            *length = match symbol {
                0..=143 => 8,
                144..=255 => 9,
                256..=279 => 7,
                _ => 8,
            };
        }
        Ok(HuffmanTree::from_lengths(&lengths)?)
    }

    /// The distance code every fixed block uses.
    pub fn offsets() -> Result<HuffmanTree, DeflateError> {
        Ok(HuffmanTree::from_lengths(&[5; 32])?)
    }

    /// The symbol, base and extra bits a match length is written as.
    pub fn length(length: usize) -> (usize, u32, u8) {
        let symbol = Self::LENGTHS.partition_point(|(base, _)| *base as usize <= length).saturating_sub(1);
        let (base, extra) = Self::LENGTHS[symbol];
        (257 + symbol, (length.saturating_sub(base as usize)) as u32, extra)
    }

    /// The symbol, base and extra bits a match distance is written as.
    pub fn offset(distance: usize) -> (usize, u32, u8) {
        let symbol = Self::OFFSETS.partition_point(|(base, _)| *base as usize <= distance).saturating_sub(1);
        let (base, extra) = Self::OFFSETS[symbol];
        (symbol, (distance.saturating_sub(base as usize)) as u32, extra)
    }

    /// The widest distance a match may reach back, which the window sets.
    pub fn window(&self) -> usize {
        1usize << self.window.clamp(9, 15)
    }

    /// The tokens LZ77 matching finds in `data`, which every compressed block writes.
    pub fn tokens(&self, data: &[u8]) -> Vec<DeflateToken> {
        let mut matcher = LZ77Matcher::new(self.window(), Self::MAXIMUM_MATCH, data.len());
        let mut tokens = Vec::with_capacity(data.len() / 4 + 1);
        let mut offset = 0;
        while offset < data.len() {
            match matcher.find(data, offset, Self::MINIMUM_MATCH, data.len() - offset) {
                Some((distance, length)) => {
                    tokens.push(DeflateToken::Match { distance: distance as u16, length: length as u16 });
                    for step in 0..length {
                        matcher.insert(data, offset + step);
                    }
                    offset += length;
                }
                None => {
                    tokens.push(DeflateToken::Literal(data[offset]));
                    matcher.insert(data, offset);
                    offset += 1;
                }
            }
        }
        tokens
    }

    /// Encodes `data` as the smallest block the format names, which is what the builtin codec writes.
    ///
    /// A level of zero asks for no compression at all, which stored blocks carry.
    pub fn encode(&self, data: &[u8]) -> Result<Vec<u8>, DeflateError> {
        if self.level == 0 {
            return Ok(self.store(data));
        }
        let tokens = self.tokens(data);
        let mut best = self.block(data, &tokens, DeflateBlock::Fixed)?;
        let candidate = self.block(data, &tokens, DeflateBlock::Dynamic)?;
        if candidate.len() < best.len() {
            best = candidate;
        }
        match best.len() < self.stored_len(data) {
            true => Ok(best),
            false => Ok(self.store(data)),
        }
    }

    /// The number of bytes `store` spends on `data`, which every compressed block is measured against.
    pub fn stored_len(&self, data: &[u8]) -> usize {
        data.len().div_ceil(Self::STORED).max(1) * 5 + data.len()
    }

    /// Encodes `data` as one final block of `kind`, whose symbols `tokens` carries.
    pub fn block(&self, data: &[u8], tokens: &[DeflateToken], kind: DeflateBlock) -> Result<Vec<u8>, DeflateError> {
        let codes = match kind {
            DeflateBlock::Stored => return Ok(self.store(data)),
            DeflateBlock::Fixed => DeflateCodes::fixed()?,
            DeflateBlock::Dynamic => DeflateCodes::from_tokens(tokens)?,
        };
        let mut writer = DeflateWriter::new();
        writer.write(1, 1);
        writer.write(kind.bits(), 2);
        if kind == DeflateBlock::Dynamic {
            codes.write(&mut writer)?;
        }
        self.deflate(&mut writer, tokens, &codes)?;
        Ok(writer.finish())
    }

    /// Writes `tokens` through `codes`, closing with the symbol that ends a block.
    pub fn deflate(&self, writer: &mut DeflateWriter, tokens: &[DeflateToken], codes: &DeflateCodes) -> Result<(), DeflateError> {
        for token in tokens {
            match token {
                DeflateToken::Literal(byte) => {
                    let (code, length) = codes.literals.encode(*byte as usize).ok_or(DeflateError::Format)?;
                    writer.code(code, length);
                }
                DeflateToken::Match { distance, length } => {
                    let (symbol, extra, bits) = Self::length(*length as usize);
                    let (code, code_length) = codes.literals.encode(symbol).ok_or(DeflateError::Format)?;
                    writer.code(code, code_length);
                    writer.write(extra, bits);
                    let (symbol, extra, bits) = Self::offset(*distance as usize);
                    let (code, code_length) = codes.offsets.encode(symbol).ok_or(DeflateError::Format)?;
                    writer.code(code, code_length);
                    writer.write(extra, bits);
                }
            }
        }
        let (code, length) = codes.literals.encode(Self::END).ok_or(DeflateError::Format)?;
        writer.code(code, length);
        Ok(())
    }

    /// Encodes `data` as stored blocks, which never grow it by more than five bytes per block.
    pub fn store(&self, data: &[u8]) -> Vec<u8> {
        let mut writer = DeflateWriter::new();
        let blocks = data.len().div_ceil(Self::STORED).max(1);
        for index in 0..blocks {
            let start = index * Self::STORED;
            let block = &data[start..(start + Self::STORED).min(data.len())];
            writer.write(u32::from(index + 1 == blocks), 1);
            writer.write(0, 2);
            writer.align();
            writer.write(block.len() as u32, 16);
            writer.write(!(block.len() as u32) & 0xFFFF, 16);
            writer.bytes(block);
        }
        writer.finish()
    }

    /// Decodes a DEFLATE stream, which is what the builtin codec reads.
    pub fn decode(&self, data: &[u8]) -> Result<Vec<u8>, DeflateError> {
        Ok(self.inflate_stream(data)?.0)
    }

    /// Decodes a DEFLATE stream and reports how many bytes of `data` it spent.
    pub fn inflate_stream(&self, data: &[u8]) -> Result<(Vec<u8>, usize), DeflateError> {
        let mut reader = DeflateReader::new(data);
        let mut output = Vec::new();
        loop {
            let last = reader.bit()? == 1;
            match DeflateBlock::from_bits(reader.bits(2)?)? {
                DeflateBlock::Stored => {
                    reader.align();
                    let length = reader.bits(16)? as usize;
                    let check = reader.bits(16)?;
                    if check != !(length as u32) & 0xFFFF {
                        return Err(DeflateError::Format);
                    }
                    if self.limit.is_some_and(|limit| output.len() + length > limit) {
                        return Err(DeflateError::Limit);
                    }
                    output.extend_from_slice(reader.take(length)?);
                }
                DeflateBlock::Fixed => self.inflate(&mut reader, &mut output, &DeflateCodes::fixed()?)?,
                DeflateBlock::Dynamic => {
                    let codes = DeflateCodes::read(&mut reader)?;
                    self.inflate(&mut reader, &mut output, &codes)?;
                }
            }
            if last {
                return Ok((output, reader.align()));
            }
        }
    }

    /// Reads the symbols of one compressed block into `output`.
    pub fn inflate(&self, reader: &mut DeflateReader<'_>, output: &mut Vec<u8>, codes: &DeflateCodes) -> Result<(), DeflateError> {
        loop {
            let symbol = reader.symbol(&codes.literals)?;
            match symbol {
                Self::END => return Ok(()),
                literal if literal < Self::END => {
                    if self.limit.is_some_and(|limit| output.len() >= limit) {
                        return Err(DeflateError::Limit);
                    }
                    output.push(literal as u8);
                }
                symbol if symbol - 257 < Self::LENGTHS.len() => {
                    let (base, extra) = Self::LENGTHS[symbol - 257];
                    let length = base as usize + reader.bits(extra)? as usize;
                    let symbol = reader.symbol(&codes.offsets)?;
                    let (base, extra) = *Self::OFFSETS.get(symbol).ok_or(DeflateError::Format)?;
                    let distance = base as usize + reader.bits(extra)? as usize;
                    if distance > output.len() {
                        return Err(DeflateError::Format);
                    }
                    if self.limit.is_some_and(|limit| output.len() + length > limit) {
                        return Err(DeflateError::Limit);
                    }
                    let start = output.len() - distance;
                    match distance >= length {
                        true => output.extend_from_within(start..start + length),
                        false => {
                            output.reserve(length);
                            for step in 0..length {
                                output.push(output[start + step]);
                            }
                        }
                    }
                }
                _ => return Err(DeflateError::Format),
            }
        }
    }
}

#[derive(Debug)]
pub struct DeflateEncoder {
    options: Deflate,
    input: Vec<u8>,
    backend: ProviderBackend<dyn CodecProvider>,
}

impl DeflateEncoder {
    pub fn new(options: Deflate) -> Self {
        match CodecProviders::backend(&options.request(CodecDirection::Encode)) {
            ProviderBackend::Builtin => Self { options, input: Vec::new(), backend: ProviderBackend::Builtin },
            backend => Self { options, input: Vec::new(), backend },
        }
    }

    pub fn options(&self) -> &Deflate {
        &self.options
    }

    /// Holds `data` until the stream is finalized, which is when the builtin codec runs.
    pub fn update(&mut self, data: &[u8]) -> Result<Vec<u8>, DeflateError> {
        match &self.backend {
            ProviderBackend::Builtin => {
                self.input.extend_from_slice(data);
                Ok(Vec::new())
            }
            ProviderBackend::Handle { provider, handle } => Ok(provider.update(*handle, data)?),
        }
    }

    pub fn finalize(self) -> Result<Vec<u8>, DeflateError> {
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
pub struct DeflateDecoder {
    options: Deflate,
    input: Vec<u8>,
    backend: ProviderBackend<dyn CodecProvider>,
}

impl DeflateDecoder {
    pub fn new(options: Deflate) -> Self {
        match CodecProviders::backend(&options.request(CodecDirection::Decode)) {
            ProviderBackend::Builtin => Self { options, input: Vec::new(), backend: ProviderBackend::Builtin },
            backend => Self { options, input: Vec::new(), backend },
        }
    }

    pub fn options(&self) -> &Deflate {
        &self.options
    }

    /// Holds `data` until the stream is finalized, which is when the builtin codec runs.
    pub fn update(&mut self, data: &[u8]) -> Result<Vec<u8>, DeflateError> {
        match &self.backend {
            ProviderBackend::Builtin => {
                self.input.extend_from_slice(data);
                Ok(Vec::new())
            }
            ProviderBackend::Handle { provider, handle } => Ok(provider.update(*handle, data)?),
        }
    }

    pub fn finalize(self) -> Result<Vec<u8>, DeflateError> {
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

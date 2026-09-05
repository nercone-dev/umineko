use alloc::vec;
use alloc::vec::Vec;
use crate::errors::ZstandardError;

use umineko_codec_huffman::HuffmanTree;
use umineko_codec_lz77::LZ77Matcher;

use umineko_hash_xxhash::XXH64;

use umineko_helpers::provider::{CodecDirection, CodecProvider, CodecProviderRequest, CodecProviders, ProviderBackend};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Zstandard {
    pub level: i8,
    pub window: u8,
        pub limit: Option<usize>,
}

impl Default for Zstandard {
    fn default() -> Self {
        Self {
            level: 3,
            window: 23,
            limit: None,
        }
    }
}

impl Zstandard {
    pub const NAME: &'static str = "zstd";

    pub fn request(&self, direction: CodecDirection) -> CodecProviderRequest<'_> {
        CodecProviderRequest::new(Self::NAME, direction).with_level(self.level as i32).with_window(self.window).with_limit(self.limit)
    }

    pub fn encoder(&self) -> ZstandardEncoder {
        ZstandardEncoder::new(self.clone())
    }

    pub fn decoder(&self) -> ZstandardDecoder {
        ZstandardDecoder::new(self.clone())
    }

    pub fn compress(&self, data: &[u8]) -> Result<Vec<u8>, ZstandardError> {
        match CodecProviders::transform(&self.request(CodecDirection::Encode), data)? {
            Some(output) => Ok(output),
            None => self.encode(data),
        }
    }

    pub fn decompress(&self, data: &[u8]) -> Result<Vec<u8>, ZstandardError> {
        match CodecProviders::transform(&self.request(CodecDirection::Decode), data)? {
            Some(output) => Ok(output),
            None => self.decode(data),
        }
    }
}

/// Reads the bits of a block backwards, as the format writes them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZstandardBits<'a> {
    storage: &'a [u8],
    position: isize,
}

impl<'a> ZstandardBits<'a> {
    pub fn new(storage: &'a [u8]) -> Result<Self, ZstandardError> {
        let last = *storage.last().ok_or(ZstandardError::Truncated)?;
        if last == 0 {
            return Err(ZstandardError::Format);
        }
        let padding = last.leading_zeros() as isize + 1;
        Ok(Self { storage, position: storage.len() as isize * 8 - padding })
    }

    /// The bit at `index`, counted from the least significant bit of the first byte.
    pub fn at(&self, index: isize) -> u32 {
        match index >= 0 {
            true => (self.storage[index as usize / 8] >> (index as usize % 8)) as u32 & 1,
            false => 0,
        }
    }

    /// Reads `length` bits and moves past them; bits past the start of the stream read as zero.
    pub fn read(&mut self, length: u32) -> u32 {
        let value = self.peek(length);
        self.skip(length);
        value
    }

    pub fn peek(&self, length: u32) -> u32 {
        let start = self.position - length as isize;
        if length == 0 || start < 0 {
            let mut value = 0;
            for step in 1..=length as isize {
                value = (value << 1) | self.at(self.position - step);
            }
            return value;
        }
        let (index, shift) = (start as usize / 8, start as usize % 8);
        let mut window = [0u8; 8];
        let taken = self.storage.len().saturating_sub(index).min(window.len());
        window[..taken].copy_from_slice(&self.storage[index..index + taken]);
        ((u64::from_le_bytes(window) >> shift) & (u64::MAX >> (64 - length))) as u32
    }

    pub fn skip(&mut self, length: u32) {
        self.position -= length as isize;
    }

    /// Whether the stream has been read past its start.
    pub fn overrun(&self) -> bool {
        self.position < 0
    }

    pub fn position(&self) -> isize {
        self.position
    }
}

/// Reads the bits of a table description forwards, least significant bit first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZstandardForward<'a> {
    storage: &'a [u8],
    position: usize,
}

impl<'a> ZstandardForward<'a> {
    pub fn new(storage: &'a [u8]) -> Self {
        Self { storage, position: 0 }
    }

    pub fn read(&mut self, length: u32) -> Result<u32, ZstandardError> {
        let (mut value, mut filled) = (0u32, 0u32);
        while filled < length {
            let byte = *self.storage.get(self.position / 8).ok_or(ZstandardError::Truncated)?;
            let used = (self.position % 8) as u32;
            let taken = (8 - used).min(length - filled);
            value |= (((byte >> used) as u32) & (u32::MAX >> (32 - taken))) << filled;
            self.position += taken as usize;
            filled += taken;
        }
        Ok(value)
    }

    /// The bits already read, rounded up to whole bytes.
    pub fn bytes(&self) -> usize {
        self.position.div_ceil(8)
    }
}

/// Writes bits into a stream, least significant bit first, as both readers take them back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZstandardWriter {
    storage: Vec<u8>,
    holding: u64,
    held: u32,
}

impl ZstandardWriter {
    pub fn new() -> Self {
        Self { storage: Vec::new(), holding: 0, held: 0 }
    }

    pub fn write(&mut self, bits: u32, length: u32) {
        self.holding |= (bits as u64 & ((1u64 << length) - 1)) << self.held;
        self.held += length;
        while self.held >= 8 {
            self.storage.push(self.holding as u8);
            self.holding >>= 8;
            self.held -= 8;
        }
    }

    /// Pads the stream with zero bits up to the next byte, which is how a description ends.
    pub fn finish(mut self) -> Vec<u8> {
        if self.held != 0 {
            self.storage.push(self.holding as u8);
        }
        self.storage
    }

    /// Closes the stream with the marker bit a block's bits are found by, then pads.
    pub fn close(mut self) -> Vec<u8> {
        self.write(1, 1);
        self.finish()
    }

    pub fn len(&self) -> usize {
        self.storage.len()
    }

    pub fn is_empty(&self) -> bool {
        self.storage.is_empty() && self.held == 0
    }
}

impl Default for ZstandardWriter {
    fn default() -> Self {
        Self::new()
    }
}

/// A finite state entropy encoder, which walks a decoding table backwards.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZstandardStates {
    pub table: ZstandardTable,
    pub cells: Vec<Vec<usize>>,
}

impl ZstandardStates {
    /// The encoder a decoding table describes.
    pub fn new(table: ZstandardTable) -> Self {
        let mut order: Vec<usize> = (0..table.cells.len()).collect();
        order.sort_by_key(|index| table.cells[*index].base);
        let mut cells: Vec<Vec<usize>> = vec![Vec::new(); 256];
        for index in order {
            cells[table.cells[index].symbol as usize].push(index);
        }
        Self { table, cells }
    }

    /// The state a stream opens `symbol` from, which is the one that spends the most bits.
    ///
    /// Every stream that names no count ends when its reader runs past the start, so the state
    /// a stream opens from has to spend a bit at the least for that reader to ever stop.
    pub fn start(&self, symbol: u8) -> Result<usize, ZstandardError> {
        self.cells[symbol as usize].iter().copied().max_by_key(|index| self.table.cells[*index].bits).ok_or(ZstandardError::Format)
    }

    /// The state that carries `symbol` and steps to `state`, and the bits that name the step.
    pub fn step(&self, symbol: u8, state: usize) -> Result<(usize, u32, u32), ZstandardError> {
        let cells = &self.cells[symbol as usize];
        let found = cells.partition_point(|index| self.table.cells[*index].base as usize <= state);
        let index = *cells.get(found.wrapping_sub(1)).ok_or(ZstandardError::Format)?;
        let cell = self.table.cells[index];
        match state >= cell.base as usize && (state - cell.base as usize) < (1usize << cell.bits) {
            true => Ok((index, (state - cell.base as usize) as u32, cell.bits as u32)),
            false => Err(ZstandardError::Format),
        }
    }
}

/// One cell of a finite state entropy decoding table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZstandardCell {
    pub symbol: u8,
    pub bits: u8,
    pub base: u16,
}

/// A finite state entropy decoding table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZstandardTable {
    pub log: u32,
    pub cells: Vec<ZstandardCell>,
}

impl ZstandardTable {
    pub const MAXIMUM_LOG: u32 = 9;

    /// The table one symbol always decodes to.
    pub fn single(symbol: u8) -> Self {
        Self { log: 0, cells: [ZstandardCell { symbol, bits: 0, base: 0 }].to_vec() }
    }

    /// The table a normalized distribution describes.
    pub fn build(counts: &[i32], log: u32) -> Result<Self, ZstandardError> {
        let size = 1usize << log;
        let mut symbols = vec![0u8; size];
        let mut next = vec![0i32; counts.len()];
        let mut high = size - 1;
        for (symbol, count) in counts.iter().enumerate() {
            if *count == -1 {
                symbols[high] = symbol as u8;
                high = high.wrapping_sub(1);
                next[symbol] = 1;
            } else {
                next[symbol] = *count;
            }
        }
        let step = (size >> 1) + (size >> 3) + 3;
        let mask = size - 1;
        let mut position = 0;
        for (symbol, count) in counts.iter().enumerate() {
            for _ in 0..(*count).max(0) {
                symbols[position] = symbol as u8;
                position = (position + step) & mask;
                while position > high {
                    position = (position + step) & mask;
                }
            }
        }
        if position != 0 {
            return Err(ZstandardError::Format);
        }
        let mut cells = Vec::with_capacity(size);
        for symbol in symbols.iter() {
            let state = next[*symbol as usize];
            next[*symbol as usize] += 1;
            let bits = log - (31 - (state as u32).leading_zeros());
            cells.push(ZstandardCell { symbol: *symbol, bits: bits as u8, base: ((state as u32) << bits) as u16 - size as u16 });
        }
        Ok(Self { log, cells })
    }


    /// The distribution `counts` normalizes to over `1 << log` cells.
    pub fn normalize(counts: &[u32], log: u32) -> Vec<i32> {
        let size = 1i64 << log;
        let total: i64 = counts.iter().map(|count| *count as i64).sum();
        let mut normalized = vec![0i32; counts.len()];
        if total == 0 {
            return normalized;
        }
        let mut assigned = 0i64;
        for (symbol, count) in counts.iter().enumerate().filter(|(_, count)| **count > 0) {
            normalized[symbol] = (((*count as i64 * size + total / 2) / total) as i32).max(1);
            assigned += normalized[symbol] as i64;
        }
        while assigned != size {
            let step = match assigned > size {
                true => -1,
                false => 1,
            };
            let candidate = (0..normalized.len()).filter(|symbol| normalized[*symbol] > 1 - step.max(0)).max_by_key(|symbol| normalized[*symbol]);
            match candidate {
                Some(symbol) => {
                    normalized[symbol] += step;
                    assigned += step as i64;
                }
                None => break,
            }
        }
        normalized
    }

    /// The accuracy a distribution of `symbols` symbols over `total` counts is written at.
    pub fn accuracy(symbols: usize, total: usize, maximum: u32) -> u32 {
        let needed = usize::BITS - symbols.saturating_sub(1).leading_zeros();
        let wanted = (usize::BITS - total.max(1).leading_zeros()).saturating_sub(1);
        needed.max(wanted).clamp(5, maximum)
    }

    /// The bytes a normalized distribution is described by, which `read` takes back.
    pub fn write(counts: &[i32], log: u32) -> Vec<u8> {
        let mut writer = ZstandardWriter::new();
        writer.write(log - 5, 4);
        let size = 1i32 << log;
        let mut remaining = size + 1;
        let mut threshold = size;
        let mut bits = log + 1;
        let mut symbol = 0;
        while remaining > 1 && symbol < counts.len() {
            let count = counts[symbol];
            symbol += 1;
            let maximum = (2 * threshold - 1) - remaining;
            let value = count + 1;
            match value < maximum {
                true => writer.write(value as u32, bits - 1),
                false => writer.write(match value >= threshold {
                    true => value + maximum,
                    false => value,
                } as u32, bits),
            }
            remaining -= count.abs();
            if count == 0 {
                let mut run = 0;
                while symbol < counts.len() && counts[symbol] == 0 {
                    run += 1;
                    symbol += 1;
                }
                while run >= 3 {
                    writer.write(3, 2);
                    run -= 3;
                }
                writer.write(run, 2);
            }
            while remaining < threshold {
                bits -= 1;
                threshold >>= 1;
            }
        }
        writer.finish()
    }

    /// The normalized distribution a table description carries, and the bytes it spends.
    pub fn read(data: &[u8], maximum_symbol: usize, maximum_log: u32) -> Result<(Vec<i32>, u32, usize), ZstandardError> {
        let mut reader = ZstandardForward::new(data);
        let log = reader.read(4)? + 5;
        if log > maximum_log {
            return Err(ZstandardError::Format);
        }
        let size = 1i32 << log;
        let mut remaining = size + 1;
        let mut threshold = size;
        let mut bits = log + 1;
        let mut counts = vec![0i32; maximum_symbol + 1];
        let mut symbol = 0;
        let mut previous = false;
        while remaining > 1 && symbol <= maximum_symbol {
            if previous {
                let mut zeroes = 0;
                loop {
                    let flags = reader.read(2)?;
                    zeroes += flags;
                    if flags != 3 {
                        break;
                    }
                }
                for _ in 0..zeroes {
                    if symbol > maximum_symbol {
                        return Err(ZstandardError::Format);
                    }
                    counts[symbol] = 0;
                    symbol += 1;
                }
                previous = false;
                continue;
            }
            let maximum = (2 * threshold - 1) - remaining;
            let value = reader.read(bits - 1)? as i32;
            let count = match value < maximum {
                true => value,
                false => {
                    let extra = reader.read(1)? as i32;
                    let value = value | (extra << (bits - 1));
                    match value >= threshold {
                        true => value - maximum,
                        false => value,
                    }
                }
            } - 1;
            remaining -= count.abs();
            counts[symbol] = count;
            symbol += 1;
            previous = count == 0;
            while remaining < threshold {
                bits -= 1;
                threshold >>= 1;
            }
        }
        match remaining == 1 {
            true => Ok((counts, log, reader.bytes())),
            false => Err(ZstandardError::Format),
        }
    }
}

/// A Huffman decoding table, indexed by the widest code it holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZstandardHuffman {
    pub log: u32,
    pub weights: Vec<u8>,
    pub symbols: Vec<u8>,
    pub bits: Vec<u8>,
}

impl ZstandardHuffman {
    pub const MAXIMUM_LOG: u32 = 11;
    /// The accuracy the weights of a Huffman table are coded at.
    pub const WEIGHT_LOG: u32 = 6;
    /// The most weights a description writes one nibble each.
    pub const DIRECT: usize = 128;
    /// The most bytes an entropy coded description spends.
    pub const DESCRIBED: usize = 127;

    /// The table a run of weights describes.
    pub fn build(weights: &[u8]) -> Result<Self, ZstandardError> {
        let total: u32 = weights.iter().map(|weight| match weight {
            0 => 0,
            weight => 1u32 << (weight - 1),
        }).sum();
        if total == 0 {
            return Err(ZstandardError::Format);
        }
        let log = 32 - total.leading_zeros();
        let last = (1u32 << log) - total;
        if !last.is_power_of_two() {
            return Err(ZstandardError::Format);
        }
        let mut weights = weights.to_vec();
        weights.push((last.trailing_zeros() + 1) as u8);
        if log > Self::MAXIMUM_LOG {
            return Err(ZstandardError::Format);
        }
        let size = 1usize << log;
        let mut symbols = vec![0u8; size];
        let mut bits = vec![0u8; size];
        let mut position = 0;
        for weight in 1..=log as u8 {
            for (symbol, entry) in weights.iter().enumerate() {
                if *entry == weight {
                    let width = 1usize << (weight - 1);
                    if position + width > size {
                        return Err(ZstandardError::Format);
                    }
                    for index in position..position + width {
                        symbols[index] = symbol as u8;
                        bits[index] = (log as u8) + 1 - weight;
                    }
                    position += width;
                }
            }
        }
        match position == size {
            true => Ok(Self { log, weights, symbols, bits }),
            false => Err(ZstandardError::Format),
        }
    }

    /// The table the byte frequencies of a block's literals ask for.
    pub fn from_frequencies(frequencies: &[u32]) -> Result<Self, ZstandardError> {
        let tree = HuffmanTree::from_frequencies(frequencies, Self::MAXIMUM_LOG as u8).map_err(|_| ZstandardError::Format)?;
        let log = tree.lengths().iter().copied().max().unwrap_or(0);
        let last = tree.lengths().iter().rposition(|length| *length > 0).ok_or(ZstandardError::Format)?;
        let weights: Vec<u8> = tree.lengths()[..last].iter().map(|length| match length {
            0 => 0,
            length => log + 1 - length,
        }).collect();
        Self::build(&weights)
    }

    /// The code and length of every symbol the table carries, which `symbol` reads back.
    pub fn codes(&self) -> Vec<(u16, u8)> {
        let mut codes = vec![(0u16, 0u8); self.weights.len()];
        let mut position = 0usize;
        for weight in 1..=self.log as u8 {
            for (symbol, _) in self.weights.iter().enumerate().filter(|(_, entry)| **entry == weight) {
                codes[symbol] = ((position >> (weight - 1)) as u16, self.log as u8 + 1 - weight);
                position += 1usize << (weight - 1);
            }
        }
        codes
    }

    /// The bytes a tree description spends, which `read` takes back.
    ///
    /// A description holds every weight but the last, which the table it completes names.
    pub fn write(&self) -> Result<Vec<u8>, ZstandardError> {
        let listed = self.weights.len().checked_sub(1).ok_or(ZstandardError::Format)?;
        if listed <= Self::DIRECT {
            let mut output = Vec::with_capacity(1 + listed.div_ceil(2));
            output.push((listed + 127) as u8);
            for pair in self.weights[..listed].chunks(2) {
                output.push((pair[0] << 4) | pair.get(1).copied().unwrap_or(0));
            }
            return Ok(output);
        }
        let described = Self::describe(&self.weights[..listed])?;
        if described.is_empty() || described.len() > Self::DESCRIBED {
            return Err(ZstandardError::Format);
        }
        let mut output = Vec::with_capacity(1 + described.len());
        output.push(described.len() as u8);
        output.extend_from_slice(&described);
        Ok(output)
    }

    /// The bytes an entropy coded description of `weights` spends, which `weights_of` takes back.
    pub fn describe(weights: &[u8]) -> Result<Vec<u8>, ZstandardError> {
        if weights.len() < 2 {
            return Err(ZstandardError::Format);
        }
        let mut counts = vec![0u32; Self::MAXIMUM_LOG as usize + 1];
        for weight in weights {
            *counts.get_mut(*weight as usize).ok_or(ZstandardError::Format)? += 1;
        }
        let symbols = counts.iter().filter(|count| **count > 0).count();
        if symbols < 2 {
            return Err(ZstandardError::Format);
        }
        let log = ZstandardTable::accuracy(symbols, weights.len(), Self::WEIGHT_LOG);
        let normalized = ZstandardTable::normalize(&counts, log);
        let states = ZstandardStates::new(ZstandardTable::build(&normalized, log)?);
        let mut output = ZstandardTable::write(&normalized, log);
        output.extend_from_slice(&Self::encode_weights(weights, &states)?);
        Ok(output)
    }

    /// Writes `weights` through two interleaved states, which `weights_of` reads back.
    ///
    /// The two states carry the even and the odd weights, and the pair the stream opens from is
    /// never written; the reader takes those two back when it runs past the start of the stream.
    pub fn encode_weights(weights: &[u8], states: &ZstandardStates) -> Result<Vec<u8>, ZstandardError> {
        let count = weights.len();
        if count < 2 {
            return Err(ZstandardError::Format);
        }
        let mut writer = ZstandardWriter::new();
        let mut current = [0usize; 2];
        current[(count - 1) % 2] = states.start(weights[count - 1])?;
        current[(count - 2) % 2] = states.start(weights[count - 2])?;
        for index in (0..count - 2).rev() {
            let (cell, value, bits) = states.step(weights[index], current[index % 2])?;
            writer.write(value, bits);
            current[index % 2] = cell;
        }
        writer.write(current[1] as u32, states.table.log);
        writer.write(current[0] as u32, states.table.log);
        Ok(writer.close())
    }


    /// The table a tree description carries, and the bytes it spends.
    pub fn read(data: &[u8]) -> Result<(Self, usize), ZstandardError> {
        let header = *data.first().ok_or(ZstandardError::Truncated)? as usize;
        match header >= 128 {
            true => {
                let count = header - 127;
                let bytes = count.div_ceil(2);
                if data.len() < 1 + bytes {
                    return Err(ZstandardError::Truncated);
                }
                let mut weights = Vec::with_capacity(count);
                for index in 0..count {
                    let byte = data[1 + index / 2];
                    weights.push(match index % 2 {
                        0 => byte >> 4,
                        _ => byte & 0x0F,
                    });
                }
                Ok((Self::build(&weights)?, 1 + bytes))
            }
            false => {
                if data.len() < 1 + header {
                    return Err(ZstandardError::Truncated);
                }
                let (counts, log, spent) = ZstandardTable::read(&data[1..1 + header], 255, Self::WEIGHT_LOG)?;
                let table = ZstandardTable::build(&counts, log)?;
                let weights = Self::weights(&data[1 + spent..1 + header], &table)?;
                Ok((Self::build(&weights)?, 1 + header))
            }
        }
    }

    /// The weights an entropy coded description carries, read through two interleaved states.
    pub fn weights(data: &[u8], table: &ZstandardTable) -> Result<Vec<u8>, ZstandardError> {
        let mut reader = ZstandardBits::new(data)?;
        let mut states = [reader.read(table.log) as usize, reader.read(table.log) as usize];
        let mut weights = Vec::new();
        let mut turn = 0;
        loop {
            let cell = *table.cells.get(states[turn]).ok_or(ZstandardError::Format)?;
            weights.push(cell.symbol);
            states[turn] = cell.base as usize + reader.read(cell.bits as u32) as usize;
            if reader.overrun() || weights.len() > 255 {
                weights.push(table.cells.get(states[1 - turn]).ok_or(ZstandardError::Format)?.symbol);
                return Ok(weights);
            }
            turn = 1 - turn;
        }
    }

    /// Reads one symbol out of a stream.
    pub fn symbol(&self, reader: &mut ZstandardBits<'_>) -> Result<u8, ZstandardError> {
        let index = reader.peek(self.log) as usize;
        reader.skip(self.bits[index] as u32);
        Ok(self.symbols[index])
    }
}

/// The header of one frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZstandardFrame {
    pub window: u64,
    pub content: Option<u64>,
    pub dictionary: u32,
    pub checksum: bool,
}

impl ZstandardFrame {
    pub const MAGIC: u32 = 0xFD2F_B528;
    pub const SKIPPABLE: u32 = 0x184D_2A50;

    /// The frame header at the start of `data`, and the bytes it spends.
    pub fn decode(data: &[u8]) -> Result<(Self, usize), ZstandardError> {
        if data.len() < 5 {
            return Err(ZstandardError::Truncated);
        }
        if u32::from_le_bytes([data[0], data[1], data[2], data[3]]) != Self::MAGIC {
            return Err(ZstandardError::Format);
        }
        let descriptor = data[4];
        let content_flag = descriptor >> 6;
        let single = descriptor & 0x20 != 0;
        if descriptor & 0x08 != 0 {
            return Err(ZstandardError::Format);
        }
        let checksum = descriptor & 0x04 != 0;
        let dictionary_flag = descriptor & 0x03;
        let mut offset = 5;
        let mut window = 0;
        if !single {
            let byte = *data.get(offset).ok_or(ZstandardError::Truncated)? as u64;
            offset += 1;
            let base = 1u64 << (10 + (byte >> 3));
            window = base + (base / 8) * (byte & 7);
        }
        let dictionary_size = match dictionary_flag {
            0 => 0,
            3 => 4,
            other => 1 << (other - 1),
        };
        if data.len() < offset + dictionary_size {
            return Err(ZstandardError::Truncated);
        }
        let mut dictionary = 0u32;
        for (step, byte) in data[offset..offset + dictionary_size].iter().enumerate() {
            dictionary |= (*byte as u32) << (8 * step);
        }
        offset += dictionary_size;
        let content_size = match (content_flag, single) {
            (0, true) => 1,
            (0, false) => 0,
            (1, _) => 2,
            (2, _) => 4,
            _ => 8,
        };
        if data.len() < offset + content_size {
            return Err(ZstandardError::Truncated);
        }
        let mut content = 0u64;
        for (step, byte) in data[offset..offset + content_size].iter().enumerate() {
            content |= (*byte as u64) << (8 * step);
        }
        if content_size == 2 {
            content += 256;
        }
        offset += content_size;
        Ok((Self { window, content: Some(content).filter(|_| content_size != 0), dictionary, checksum }, offset))
    }

    /// The bytes of a frame header that carries `length` bytes of content.
    pub fn encode(length: usize, checksum: bool) -> Vec<u8> {
        let mut output = Vec::with_capacity(14);
        output.extend_from_slice(&Self::MAGIC.to_le_bytes());
        let (flag, size) = match length {
            0..=255 => (0u8, 1),
            256..=65791 => (1, 2),
            length if length <= u32::MAX as usize => (2, 4),
            _ => (3, 8),
        };
        output.push((flag << 6) | 0x20 | (u8::from(checksum) << 2));
        let stored = match size {
            2 => length as u64 - 256,
            _ => length as u64,
        };
        output.extend_from_slice(&stored.to_le_bytes()[..size]);
        output
    }
}

/// The kind of block a frame carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZstandardBlock {
    Raw,
    RLE,
    Compressed,
}

impl ZstandardBlock {
    /// The two bits a block header names this kind with.
    pub fn bits(&self) -> u32 {
        match self {
            Self::Raw => 0,
            Self::RLE => 1,
            Self::Compressed => 2,
        }
    }

    /// The kind the two bits of a block header name.
    pub fn from_bits(bits: u32) -> Result<Self, ZstandardError> {
        match bits {
            0 => Ok(Self::Raw),
            1 => Ok(Self::RLE),
            2 => Ok(Self::Compressed),
            _ => Err(ZstandardError::Format),
        }
    }

    /// The bytes a block of `size` carries, which one repeated byte fits in a single one of.
    pub fn stored(&self, size: usize) -> usize {
        match self {
            Self::RLE => 1,
            _ => size,
        }
    }

    /// The header one block opens with, which names the content that follows it.
    pub fn header(&self, size: usize, last: bool) -> [u8; 3] {
        let header = u32::from(last) | (self.bits() << 1) | ((size as u32) << 3);
        [header as u8, (header >> 8) as u8, (header >> 16) as u8]
    }
}

/// One sequence of a block: a run of literals, then a match at some offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZstandardSequence {
    pub literals: usize,
    pub offset: usize,
    pub matched: usize,
}

impl Zstandard {
    /// The bytes one block header spends.
    pub const BLOCK_HEADER: usize = 3;
    /// The most content one block carries.
    pub const BLOCK_SIZE: usize = 128 * 1024;
    /// The number of literal length codes.
    pub const LITERAL_CODES: usize = 35;
    /// The number of match length codes.
    pub const MATCH_CODES: usize = 52;
    /// The number of offset codes a stream may carry.
    pub const OFFSET_CODES: usize = 31;
    /// The number of earlier offsets a sequence may repeat, which every named offset steps past.
    pub const REPEATS: usize = 3;
    /// The most literals one Huffman coded stream carries before four of them share the work.
    pub const SINGLE: usize = 1023;
    /// The base and extra bits of every literal length code.
    pub const LITERAL_LENGTHS: [(u32, u32); 36] = [
        (0, 0), (1, 0), (2, 0), (3, 0), (4, 0), (5, 0), (6, 0), (7, 0),
        (8, 0), (9, 0), (10, 0), (11, 0), (12, 0), (13, 0), (14, 0), (15, 0),
        (16, 1), (18, 1), (20, 1), (22, 1), (24, 2), (28, 2), (32, 3), (40, 3),
        (48, 4), (64, 6), (128, 7), (256, 8), (512, 9), (1024, 10), (2048, 11), (4096, 12),
        (8192, 13), (16384, 14), (32768, 15), (65536, 16),
    ];
    /// The base and extra bits of every match length code.
    pub const MATCH_LENGTHS: [(u32, u32); 53] = [
        (3, 0), (4, 0), (5, 0), (6, 0), (7, 0), (8, 0), (9, 0), (10, 0),
        (11, 0), (12, 0), (13, 0), (14, 0), (15, 0), (16, 0), (17, 0), (18, 0),
        (19, 0), (20, 0), (21, 0), (22, 0), (23, 0), (24, 0), (25, 0), (26, 0),
        (27, 0), (28, 0), (29, 0), (30, 0), (31, 0), (32, 0), (33, 0), (34, 0),
        (35, 1), (37, 1), (39, 1), (41, 1), (43, 2), (47, 2), (51, 3), (59, 3),
        (67, 4), (83, 4), (99, 5), (131, 7), (259, 8), (515, 9), (1027, 10), (2051, 11),
        (4099, 12), (8195, 13), (16387, 14), (32771, 15), (65539, 16),
    ];
    /// The distribution literal lengths follow when a block names no table.
    pub const LITERAL_DEFAULT: [i32; 36] = [
        4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 3, 2, 1, 1, 1, 1, 1, -1, -1, -1, -1,
    ];
    /// The distribution match lengths follow when a block names no table.
    pub const MATCH_DEFAULT: [i32; 53] = [
        1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1,
        -1, -1, -1, -1, -1,
    ];
    /// The distribution offsets follow when a block names no table.
    pub const OFFSET_DEFAULT: [i32; 29] = [
        1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, -1, -1, -1, -1,
    ];

    /// The shortest and longest run a match may cover.
    pub const MINIMUM_MATCH: usize = 3;
    pub const MAXIMUM_MATCH: usize = Self::BLOCK_SIZE;

    /// The widest distance a match may reach back, which the window sets.
    pub fn window(&self) -> usize {
        1usize << self.window.clamp(10, 30)
    }

    /// The number of earlier positions one match search walks, which the level sets.
    pub fn probes(&self) -> usize {
        match self.level {
            level if level <= 1 => 8,
            2..=5 => 32,
            6..=12 => 128,
            _ => 512,
        }
    }

    /// The code, extra bits and their count a run of literals is written as.
    pub fn literal_code(length: usize) -> (usize, u32, u32) {
        let code = Self::LITERAL_LENGTHS.partition_point(|(base, _)| *base as usize <= length).saturating_sub(1);
        let (base, bits) = Self::LITERAL_LENGTHS[code];
        (code, (length - base as usize) as u32, bits)
    }

    /// The code, extra bits and their count a match length is written as.
    pub fn match_code(length: usize) -> (usize, u32, u32) {
        let code = Self::MATCH_LENGTHS.partition_point(|(base, _)| *base as usize <= length).saturating_sub(1);
        let (base, bits) = Self::MATCH_LENGTHS[code];
        (code, (length - base as usize) as u32, bits)
    }

    /// The code, extra bits and their count a match offset is written as.
    pub fn offset_code(offset: usize) -> (usize, u32, u32) {
        let code = (usize::BITS - 1 - offset.max(1).leading_zeros()) as usize;
        (code, (offset - (1 << code)) as u32, code as u32)
    }

    /// Encodes `data` as one frame, which is what the builtin codec writes.
    pub fn encode(&self, data: &[u8]) -> Result<Vec<u8>, ZstandardError> {
        let mut output = ZstandardFrame::encode(data.len(), true);
        let mut matcher = LZ77Matcher::new(self.window(), Self::MAXIMUM_MATCH, data.len()).with_probes(self.probes());
        let blocks = data.len().div_ceil(Self::BLOCK_SIZE).max(1);
        for index in 0..blocks {
            let start = index * Self::BLOCK_SIZE;
            let end = (start + Self::BLOCK_SIZE).min(data.len());
            output.extend_from_slice(&self.pack(data, start, end, index + 1 == blocks, &mut matcher)?);
        }
        output.extend_from_slice(&(XXH64::hash(data, 0) as u32).to_le_bytes());
        Ok(output)
    }

    /// Packs one block of `data` into the smallest shape the format names.
    pub fn pack(&self, data: &[u8], start: usize, end: usize, last: bool, matcher: &mut LZ77Matcher) -> Result<Vec<u8>, ZstandardError> {
        let block = &data[start..end];
        let mut best = ZstandardBlock::Raw.header(block.len(), last).to_vec();
        best.extend_from_slice(block);
        if let Some(byte) = block.first().filter(|byte| block.iter().all(|entry| entry == *byte)) {
            let mut candidate = ZstandardBlock::RLE.header(block.len(), last).to_vec();
            candidate.push(*byte);
            if candidate.len() < best.len() {
                best = candidate;
            }
        }
        let (literals, sequences) = self.tokens(data, start, end, matcher);
        if let Ok(content) = self.encode_block(&literals, &sequences) {
            if Self::BLOCK_HEADER + content.len() < best.len() {
                let mut candidate = ZstandardBlock::Compressed.header(content.len(), last).to_vec();
                candidate.extend_from_slice(&content);
                best = candidate;
            }
        }
        Ok(best)
    }

    /// The literals and sequences LZ77 matching finds in one block of `data`.
    pub fn tokens(&self, data: &[u8], start: usize, end: usize, matcher: &mut LZ77Matcher) -> (Vec<u8>, Vec<ZstandardSequence>) {
        let mut literals = Vec::new();
        let mut sequences = Vec::new();
        let mut run = 0;
        let mut offset = start;
        while offset < end {
            match matcher.find(data, offset, Self::MINIMUM_MATCH, end - offset) {
                Some((distance, length)) => {
                    sequences.push(ZstandardSequence { literals: run, offset: distance + Self::REPEATS, matched: length });
                    run = 0;
                    for step in 0..length {
                        matcher.insert(data, offset + step);
                    }
                    offset += length;
                }
                None => {
                    literals.push(data[offset]);
                    run += 1;
                    matcher.insert(data, offset);
                    offset += 1;
                }
            }
        }
        (literals, sequences)
    }

    /// The content one compressed block carries, which `decode_block` reads back.
    pub fn encode_block(&self, literals: &[u8], sequences: &[ZstandardSequence]) -> Result<Vec<u8>, ZstandardError> {
        let mut output = self.encode_literals(literals)?;
        output.extend_from_slice(&self.encode_sequences(sequences)?);
        Ok(output)
    }

    /// The header a literals section opens with.
    pub fn header_literals(kind: u32, regenerated: usize) -> Vec<u8> {
        match regenerated {
            0..=31 => (kind | ((regenerated as u32) << 3)).to_le_bytes()[..1].to_vec(),
            32..=4095 => (kind | (1 << 2) | ((regenerated as u32) << 4)).to_le_bytes()[..2].to_vec(),
            _ => (kind | (3 << 2) | ((regenerated as u32) << 4)).to_le_bytes()[..3].to_vec(),
        }
    }

    /// The bytes the literals section of one block spends, which `decode_literals` reads back.
    pub fn encode_literals(&self, literals: &[u8]) -> Result<Vec<u8>, ZstandardError> {
        let mut best = Self::header_literals(0, literals.len());
        best.extend_from_slice(literals);
        if let Some(byte) = literals.first().filter(|byte| literals.iter().all(|entry| entry == *byte)) {
            let mut candidate = Self::header_literals(1, literals.len());
            candidate.push(*byte);
            if candidate.len() < best.len() {
                best = candidate;
            }
        }
        if let Ok(candidate) = Self::compress_literals(literals) {
            if candidate.len() < best.len() {
                best = candidate;
            }
        }
        Ok(best)
    }

    /// The bytes a Huffman coded literals section spends, tree description and streams alike.
    pub fn compress_literals(literals: &[u8]) -> Result<Vec<u8>, ZstandardError> {
        let mut frequencies = vec![0u32; 256];
        for byte in literals {
            frequencies[*byte as usize] += 1;
        }
        if frequencies.iter().filter(|frequency| **frequency > 0).count() < 2 {
            return Err(ZstandardError::Format);
        }
        let table = ZstandardHuffman::from_frequencies(&frequencies)?;
        let described = table.write()?;
        let streams = match literals.len() > Self::SINGLE {
            true => 4,
            false => 1,
        };
        let body = Self::encode_streams(literals, &table.codes(), streams)?;
        let compressed = described.len() + body.len();
        let (format, width, spent) = match (streams, literals.len().max(compressed)) {
            (1, 0..=1023) => (0u32, 10u32, 3usize),
            (_, 0..=1023) => (1, 10, 3),
            (_, 1024..=16383) => (2, 14, 4),
            (_, 16384..=262143) => (3, 18, 5),
            _ => return Err(ZstandardError::Format),
        };
        let value = ((literals.len() as u64) | ((compressed as u64) << width)) << 4;
        let mut output = (2 | ((format as u64) << 2) | value).to_le_bytes()[..spent].to_vec();
        output.extend_from_slice(&described);
        output.extend_from_slice(&body);
        Ok(output)
    }

    /// Writes `literals` as one or four Huffman coded streams, which `decode_streams` reads back.
    pub fn encode_streams(literals: &[u8], codes: &[(u16, u8)], streams: usize) -> Result<Vec<u8>, ZstandardError> {
        if streams == 1 {
            return Self::encode_stream(literals, codes);
        }
        let quarter = literals.len().div_ceil(4);
        let mut parts = Vec::with_capacity(4);
        for index in 0..4 {
            let start = (index * quarter).min(literals.len());
            let end = match index {
                3 => literals.len(),
                _ => ((index + 1) * quarter).min(literals.len()),
            };
            parts.push(Self::encode_stream(&literals[start..end], codes)?);
        }
        let mut output = Vec::new();
        for part in parts.iter().take(3) {
            if part.len() > u16::MAX as usize {
                return Err(ZstandardError::Format);
            }
            output.extend_from_slice(&(part.len() as u16).to_le_bytes());
        }
        for part in parts.iter() {
            output.extend_from_slice(part);
        }
        Ok(output)
    }

    /// Writes `literals` as one Huffman coded stream, which `decode_stream` reads back.
    pub fn encode_stream(literals: &[u8], codes: &[(u16, u8)]) -> Result<Vec<u8>, ZstandardError> {
        let mut writer = ZstandardWriter::new();
        for byte in literals.iter().rev() {
            let (code, bits) = *codes.get(*byte as usize).filter(|(_, bits)| *bits > 0).ok_or(ZstandardError::Format)?;
            writer.write(code as u32, bits as u32);
        }
        Ok(writer.close())
    }

    /// The bytes the sequences section of one block spends, which `decode_sequences` reads back.
    pub fn encode_sequences(&self, sequences: &[ZstandardSequence]) -> Result<Vec<u8>, ZstandardError> {
        let mut output = match sequences.len() {
            count @ 0..=127 => vec![count as u8],
            count @ 128..=32511 => vec![(0x80 + (count >> 8)) as u8, count as u8],
            count => vec![255, (count - 0x7F00) as u8, ((count - 0x7F00) >> 8) as u8],
        };
        if sequences.is_empty() {
            return Ok(output);
        }
        let codes = [
            sequences.iter().map(|sequence| Self::literal_code(sequence.literals).0 as u8).collect::<Vec<u8>>(),
            sequences.iter().map(|sequence| Self::offset_code(sequence.offset).0 as u8).collect(),
            sequences.iter().map(|sequence| Self::match_code(sequence.matched).0 as u8).collect(),
        ];
        let mut best: Option<Vec<u8>> = None;
        for predefined in [true, false] {
            let candidate = Self::describe_sequences(sequences, &codes, predefined);
            if let Ok(candidate) = candidate {
                if best.as_ref().is_none_or(|found| candidate.len() < found.len()) {
                    best = Some(candidate);
                }
            }
        }
        output.extend_from_slice(&best.ok_or(ZstandardError::Format)?);
        Ok(output)
    }

    /// The modes, table descriptions and bit stream one set of sequences is written under.
    pub fn describe_sequences(sequences: &[ZstandardSequence], codes: &[Vec<u8>], predefined: bool) -> Result<Vec<u8>, ZstandardError> {
        let shapes = [
            (Self::LITERAL_DEFAULT.as_slice(), Self::LITERAL_CODES, 9u32, 6u32),
            (Self::OFFSET_DEFAULT.as_slice(), Self::OFFSET_CODES, 8, 5),
            (Self::MATCH_DEFAULT.as_slice(), Self::MATCH_CODES, 9, 6),
        ];
        let mut modes = 0u8;
        let mut described = Vec::new();
        let mut states = Vec::with_capacity(3);
        for (index, (default, symbols, maximum, accuracy)) in shapes.iter().enumerate() {
            let mut counts = vec![0u32; *symbols + 1];
            for code in codes[index].iter() {
                *counts.get_mut(*code as usize).ok_or(ZstandardError::Format)? += 1;
            }
            let distinct = counts.iter().filter(|count| **count > 0).count();
            let (mode, table) = match (predefined, distinct) {
                (true, _) => match counts.len() <= default.len() || counts[default.len()..].iter().all(|count| *count == 0) {
                    true => (0u8, ZstandardTable::build(default, *accuracy)?),
                    false => return Err(ZstandardError::Format),
                },
                (false, 1) => {
                    let symbol = counts.iter().position(|count| *count > 0).ok_or(ZstandardError::Format)? as u8;
                    described.push(symbol);
                    (1, ZstandardTable::single(symbol))
                }
                (false, _) => {
                    let log = ZstandardTable::accuracy(distinct, sequences.len(), *maximum);
                    if 1usize << log < distinct {
                        return Err(ZstandardError::Format);
                    }
                    let normalized = ZstandardTable::normalize(&counts, log);
                    described.extend_from_slice(&ZstandardTable::write(&normalized, log));
                    (2, ZstandardTable::build(&normalized, log)?)
                }
            };
            modes |= mode << (6 - 2 * index);
            states.push(ZstandardStates::new(table));
        }
        let mut output = vec![modes];
        output.extend_from_slice(&described);
        output.extend_from_slice(&Self::encode_sequence_stream(sequences, codes, &states)?);
        Ok(output)
    }

    /// Writes the sequences of one block through three interleaved states.
    pub fn encode_sequence_stream(sequences: &[ZstandardSequence], codes: &[Vec<u8>], states: &[ZstandardStates]) -> Result<Vec<u8>, ZstandardError> {
        let last = sequences.len() - 1;
        let mut writer = ZstandardWriter::new();
        let mut current = [states[0].start(codes[0][last])?, states[1].start(codes[1][last])?, states[2].start(codes[2][last])?];
        Self::write_extra(&mut writer, &sequences[last]);
        for index in (0..last).rev() {
            for table in [1usize, 2, 0] {
                let (cell, value, bits) = states[table].step(codes[table][index], current[table])?;
                writer.write(value, bits);
                current[table] = cell;
            }
            Self::write_extra(&mut writer, &sequences[index]);
        }
        writer.write(current[2] as u32, states[2].table.log);
        writer.write(current[1] as u32, states[1].table.log);
        writer.write(current[0] as u32, states[0].table.log);
        Ok(writer.close())
    }

    /// Writes the extra bits of one sequence, in the order its reader takes them back.
    pub fn write_extra(writer: &mut ZstandardWriter, sequence: &ZstandardSequence) {
        let (_, extra, bits) = Self::literal_code(sequence.literals);
        writer.write(extra, bits);
        let (_, extra, bits) = Self::match_code(sequence.matched);
        writer.write(extra, bits);
        let (_, extra, bits) = Self::offset_code(sequence.offset);
        writer.write(extra, bits);
    }

    /// Decodes every frame in `data`, which is what the builtin codec reads.
    pub fn decode(&self, data: &[u8]) -> Result<Vec<u8>, ZstandardError> {
        let mut output = Vec::new();
        let mut offset = 0;
        while offset < data.len() {
            offset += self.decode_frame(&data[offset..], &mut output)?;
        }
        Ok(output)
    }

    /// Decodes one frame into `output` and reports the bytes it spent.
    pub fn decode_frame(&self, data: &[u8], output: &mut Vec<u8>) -> Result<usize, ZstandardError> {
        if data.len() >= 8 && u32::from_le_bytes([data[0], data[1], data[2], data[3]]) & 0xFFFF_FFF0 == ZstandardFrame::SKIPPABLE {
            let length = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
            return match data.len() >= 8 + length {
                true => Ok(8 + length),
                false => Err(ZstandardError::Truncated),
            };
        }
        let (frame, mut offset) = ZstandardFrame::decode(data)?;
        let start = output.len();
        let mut huffman = None;
        let mut tables: [Option<ZstandardTable>; 3] = [None, None, None];
        loop {
            if data.len() < offset + Self::BLOCK_HEADER {
                return Err(ZstandardError::Truncated);
            }
            let header = u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], 0]);
            let last = header & 1 == 1;
            let kind = ZstandardBlock::from_bits((header >> 1) & 3)?;
            let size = (header >> 3) as usize;
            offset += Self::BLOCK_HEADER;
            let stored = kind.stored(size);
            if data.len() < offset + stored {
                return Err(ZstandardError::Truncated);
            }
            let block = &data[offset..offset + stored];
            offset += stored;
            match kind {
                ZstandardBlock::Raw => self.grow(output, block.len(), |output| {
                    output.extend_from_slice(block);
                    Ok(())
                })?,
                ZstandardBlock::RLE => {
                    let byte = *block.first().ok_or(ZstandardError::Format)?;
                    self.grow(output, size, |output| {
                        output.resize(output.len() + size, byte);
                        Ok(())
                    })?;
                }
                ZstandardBlock::Compressed => self.decode_block(block, output, &mut huffman, &mut tables)?,
            }
            if last {
                break;
            }
        }
        if frame.checksum {
            if data.len() < offset + 4 {
                return Err(ZstandardError::Truncated);
            }
            let carried = u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]);
            if carried != XXH64::hash(&output[start..], 0) as u32 {
                return Err(ZstandardError::Checksum);
            }
            offset += 4;
        }
        match frame.content.is_none_or(|content| content == (output.len() - start) as u64) {
            true => Ok(offset),
            false => Err(ZstandardError::Format),
        }
    }

    /// Runs `grow` after checking that the output may take `length` more bytes.
    pub fn grow(&self, output: &mut Vec<u8>, length: usize, grow: impl FnOnce(&mut Vec<u8>) -> Result<(), ZstandardError>) -> Result<(), ZstandardError> {
        match self.limit.is_some_and(|limit| output.len() + length > limit) {
            true => Err(ZstandardError::Limit),
            false => grow(output),
        }
    }

    /// Decodes one compressed block, which carries literals and the sequences that place them.
    pub fn decode_block(&self, block: &[u8], output: &mut Vec<u8>, huffman: &mut Option<ZstandardHuffman>, tables: &mut [Option<ZstandardTable>; 3]) -> Result<(), ZstandardError> {
        let (literals, spent) = self.decode_literals(block, huffman)?;
        let sequences = self.decode_sequences(&block[spent..], tables)?;
        let mut taken = 0;
        let mut repeats = [1usize, 4, 8];
        for (length, code, matched) in sequences {
            if taken + length > literals.len() {
                return Err(ZstandardError::Format);
            }
            let offset = self.offset(code, length, &mut repeats)?;
            self.grow(output, length + matched, |output| {
                output.extend_from_slice(&literals[taken..taken + length]);
                Ok(())
            })?;
            taken += length;
            if offset > output.len() {
                return Err(ZstandardError::Format);
            }
            let start = output.len() - offset;
            for step in 0..matched {
                output.push(output[start + step]);
            }
        }
        self.grow(output, literals.len() - taken, |output| {
            output.extend_from_slice(&literals[taken..]);
            Ok(())
        })
    }

    /// The offset one sequence names, which may repeat an earlier one.
    pub fn offset(&self, code: u32, length: usize, repeats: &mut [usize; 3]) -> Result<usize, ZstandardError> {
        if code > 3 {
            let offset = code as usize - 3;
            *repeats = [offset, repeats[0], repeats[1]];
            return Ok(offset);
        }
        let index = code as usize + usize::from(length == 0);
        let offset = match index {
            1 => repeats[0],
            2 => repeats[1],
            3 => repeats[2],
            _ => repeats[0].checked_sub(1).filter(|offset| *offset > 0).ok_or(ZstandardError::Format)?,
        };
        match index {
            1 => {}
            2 => *repeats = [offset, repeats[0], repeats[2]],
            _ => *repeats = [offset, repeats[0], repeats[1]],
        }
        Ok(offset)
    }

    /// The literals of one block, and the bytes its section spends, which `encode_literals` writes.
    pub fn decode_literals(&self, block: &[u8], huffman: &mut Option<ZstandardHuffman>) -> Result<(Vec<u8>, usize), ZstandardError> {
        let header = *block.first().ok_or(ZstandardError::Truncated)?;
        let kind = header & 3;
        let format = (header >> 2) & 3;
        match kind {
            0 | 1 => {
                let (regenerated, spent) = match format {
                    0 | 2 => ((header >> 3) as usize, 1),
                    1 => {
                        let second = *block.get(1).ok_or(ZstandardError::Truncated)? as usize;
                        (((header >> 4) as usize) | (second << 4), 2)
                    }
                    _ => {
                        let second = *block.get(1).ok_or(ZstandardError::Truncated)? as usize;
                        let third = *block.get(2).ok_or(ZstandardError::Truncated)? as usize;
                        (((header >> 4) as usize) | (second << 4) | (third << 12), 3)
                    }
                };
                match kind {
                    0 => match block.len() >= spent + regenerated {
                        true => Ok((block[spent..spent + regenerated].to_vec(), spent + regenerated)),
                        false => Err(ZstandardError::Truncated),
                    },
                    _ => {
                        let byte = *block.get(spent).ok_or(ZstandardError::Truncated)?;
                        Ok((vec![byte; regenerated], spent + 1))
                    }
                }
            }
            _ => {
                let (regenerated, compressed, streams, spent) = match format {
                    0 | 1 => {
                        if block.len() < 3 {
                            return Err(ZstandardError::Truncated);
                        }
                        let value = (header as usize >> 4) | ((block[1] as usize) << 4) | ((block[2] as usize) << 12);
                        (value & 0x3FF, (value >> 10) & 0x3FF, match format {
                            0 => 1,
                            _ => 4,
                        }, 3)
                    }
                    2 => {
                        if block.len() < 4 {
                            return Err(ZstandardError::Truncated);
                        }
                        let value = (header as usize >> 4) | ((block[1] as usize) << 4) | ((block[2] as usize) << 12) | ((block[3] as usize) << 20);
                        (value & 0x3FFF, (value >> 14) & 0x3FFF, 4, 4)
                    }
                    _ => {
                        if block.len() < 5 {
                            return Err(ZstandardError::Truncated);
                        }
                        let value = (header as usize >> 4) | ((block[1] as usize) << 4) | ((block[2] as usize) << 12) | ((block[3] as usize) << 20) | ((block[4] as usize) << 28);
                        (value & 0x3FFFF, (value >> 18) & 0x3FFFF, 4, 5)
                    }
                };
                if block.len() < spent + compressed {
                    return Err(ZstandardError::Truncated);
                }
                let section = &block[spent..spent + compressed];
                let described = match kind {
                    2 => {
                        let (table, used) = ZstandardHuffman::read(section)?;
                        *huffman = Some(table);
                        used
                    }
                    _ => 0,
                };
                let table = huffman.as_ref().ok_or(ZstandardError::Format)?;
                let literals = Self::decode_streams(&section[described..], table, regenerated, streams)?;
                Ok((literals, spent + compressed))
            }
        }
    }

    /// The literals one or four Huffman coded streams carry, which `encode_streams` writes.
    pub fn decode_streams(data: &[u8], table: &ZstandardHuffman, regenerated: usize, streams: usize) -> Result<Vec<u8>, ZstandardError> {
        let mut literals = Vec::with_capacity(regenerated);
        match streams {
            1 => Self::decode_stream(data, table, regenerated, &mut literals)?,
            _ => {
                if data.len() < 6 {
                    return Err(ZstandardError::Truncated);
                }
                let first = u16::from_le_bytes([data[0], data[1]]) as usize;
                let second = u16::from_le_bytes([data[2], data[3]]) as usize;
                let third = u16::from_le_bytes([data[4], data[5]]) as usize;
                let sizes = [first, second, third];
                let total: usize = sizes.iter().sum();
                if data.len() < 6 + total {
                    return Err(ZstandardError::Truncated);
                }
                let quarter = regenerated.div_ceil(4);
                let mut offset = 6;
                for (index, size) in sizes.iter().enumerate() {
                    Self::decode_stream(&data[offset..offset + size], table, quarter, &mut literals)?;
                    offset += size;
                    let _ = index;
                }
                Self::decode_stream(&data[offset..], table, regenerated - 3 * quarter, &mut literals)?;
            }
        }
        match literals.len() == regenerated {
            true => Ok(literals),
            false => Err(ZstandardError::Format),
        }
    }

    /// Reads `count` symbols out of one Huffman coded stream, which `encode_stream` writes.
    pub fn decode_stream(data: &[u8], table: &ZstandardHuffman, count: usize, literals: &mut Vec<u8>) -> Result<(), ZstandardError> {
        let mut reader = ZstandardBits::new(data)?;
        for _ in 0..count {
            literals.push(table.symbol(&mut reader)?);
        }
        Ok(())
    }

    /// The literal length, offset code and match length of every sequence in a block.
    pub fn decode_sequences(&self, data: &[u8], tables: &mut [Option<ZstandardTable>; 3]) -> Result<Vec<(usize, u32, usize)>, ZstandardError> {
        if data.is_empty() {
            return Ok(Vec::new());
        }
        let first = data[0] as usize;
        let (count, mut offset) = match first {
            0 => return Ok(Vec::new()),
            1..=127 => (first, 1),
            128..=254 => match data.len() >= 2 {
                true => (((first - 128) << 8) + data[1] as usize, 2),
                false => return Err(ZstandardError::Truncated),
            },
            _ => match data.len() >= 3 {
                true => (data[1] as usize + ((data[2] as usize) << 8) + 0x7F00, 3),
                false => return Err(ZstandardError::Truncated),
            },
        };
        let modes = *data.get(offset).ok_or(ZstandardError::Truncated)?;
        offset += 1;
        if modes & 3 != 0 {
            return Err(ZstandardError::Format);
        }
        let shapes = [
            ((modes >> 6) & 3, Self::LITERAL_DEFAULT.as_slice(), Self::LITERAL_CODES, 9u32),
            ((modes >> 4) & 3, Self::OFFSET_DEFAULT.as_slice(), Self::OFFSET_CODES, 8),
            ((modes >> 2) & 3, Self::MATCH_DEFAULT.as_slice(), Self::MATCH_CODES, 9),
        ];
        for (index, (mode, default, maximum, log)) in shapes.iter().enumerate() {
            match mode {
                0 => tables[index] = Some(ZstandardTable::build(default, match index {
                    1 => 5,
                    _ => 6,
                })?),
                1 => {
                    let symbol = *data.get(offset).ok_or(ZstandardError::Truncated)?;
                    offset += 1;
                    tables[index] = Some(ZstandardTable::single(symbol));
                }
                2 => {
                    let (counts, accuracy, spent) = ZstandardTable::read(&data[offset..], *maximum, *log)?;
                    offset += spent;
                    tables[index] = Some(ZstandardTable::build(&counts, accuracy)?);
                }
                _ => {
                    if tables[index].is_none() {
                        return Err(ZstandardError::Format);
                    }
                }
            }
        }
        let mut reader = ZstandardBits::new(&data[offset..])?;
        let literal = tables[0].as_ref().ok_or(ZstandardError::Format)?;
        let offsets = tables[1].as_ref().ok_or(ZstandardError::Format)?;
        let matched = tables[2].as_ref().ok_or(ZstandardError::Format)?;
        let mut states = [reader.read(literal.log) as usize, reader.read(offsets.log) as usize, reader.read(matched.log) as usize];
        let mut sequences = Vec::with_capacity(count);
        for index in 0..count {
            let offset_code = offsets.cells.get(states[1]).ok_or(ZstandardError::Format)?.symbol as u32;
            let match_code = matched.cells.get(states[2]).ok_or(ZstandardError::Format)?.symbol as usize;
            let literal_code = literal.cells.get(states[0]).ok_or(ZstandardError::Format)?.symbol as usize;
            if offset_code > 31 || match_code >= Self::MATCH_LENGTHS.len() || literal_code >= Self::LITERAL_LENGTHS.len() {
                return Err(ZstandardError::Format);
            }
            let offset_value = (1u64 << offset_code) + reader.read(offset_code) as u64;
            let (base, extra) = Self::MATCH_LENGTHS[match_code];
            let match_length = base + reader.read(extra);
            let (base, extra) = Self::LITERAL_LENGTHS[literal_code];
            let literal_length = base + reader.read(extra);
            sequences.push((literal_length as usize, offset_value as u32, match_length as usize));
            if index + 1 < count {
                let cell = literal.cells[states[0]];
                states[0] = cell.base as usize + reader.read(cell.bits as u32) as usize;
                let cell = matched.cells[states[2]];
                states[2] = cell.base as usize + reader.read(cell.bits as u32) as usize;
                let cell = offsets.cells[states[1]];
                states[1] = cell.base as usize + reader.read(cell.bits as u32) as usize;
            }
        }
        Ok(sequences)
    }
}

#[derive(Debug)]
pub struct ZstandardEncoder {
    options: Zstandard,
    input: Vec<u8>,
    backend: ProviderBackend<dyn CodecProvider>,
}

impl ZstandardEncoder {
    pub fn new(options: Zstandard) -> Self {
        match CodecProviders::backend(&options.request(CodecDirection::Encode)) {
            ProviderBackend::Builtin => Self { options, input: Vec::new(), backend: ProviderBackend::Builtin },
            backend => Self { options, input: Vec::new(), backend },
        }
    }

    pub fn options(&self) -> &Zstandard {
        &self.options
    }

    /// Holds `data` until the stream is finalized, which is when the builtin codec runs.
    pub fn update(&mut self, data: &[u8]) -> Result<Vec<u8>, ZstandardError> {
        match &self.backend {
            ProviderBackend::Builtin => {
                self.input.extend_from_slice(data);
                Ok(Vec::new())
            }
            ProviderBackend::Handle { provider, handle } => Ok(provider.update(*handle, data)?),
        }
    }

    pub fn finalize(self) -> Result<Vec<u8>, ZstandardError> {
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
pub struct ZstandardDecoder {
    options: Zstandard,
    input: Vec<u8>,
    backend: ProviderBackend<dyn CodecProvider>,
}

impl ZstandardDecoder {
    pub fn new(options: Zstandard) -> Self {
        match CodecProviders::backend(&options.request(CodecDirection::Decode)) {
            ProviderBackend::Builtin => Self { options, input: Vec::new(), backend: ProviderBackend::Builtin },
            backend => Self { options, input: Vec::new(), backend },
        }
    }

    pub fn options(&self) -> &Zstandard {
        &self.options
    }

    /// Holds `data` until the stream is finalized, which is when the builtin codec runs.
    pub fn update(&mut self, data: &[u8]) -> Result<Vec<u8>, ZstandardError> {
        match &self.backend {
            ProviderBackend::Builtin => {
                self.input.extend_from_slice(data);
                Ok(Vec::new())
            }
            ProviderBackend::Handle { provider, handle } => Ok(provider.update(*handle, data)?),
        }
    }

    pub fn finalize(self) -> Result<Vec<u8>, ZstandardError> {
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

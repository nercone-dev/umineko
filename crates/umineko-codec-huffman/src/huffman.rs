use alloc::vec;
use alloc::vec::Vec;
use core::cmp::Reverse;
use crate::errors::HuffmanError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Huffman {
    Static,
    Adaptive,
}

impl Huffman {
    /// The symbol both codecs close a stream with.
    pub const END: usize = 256;
    /// The number of symbols both codecs code, the closing symbol included.
    pub const SYMBOLS: usize = 257;
    /// The longest code either codec builds.
    pub const MAXIMUM_LENGTH: u8 = 15;

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Static => "static",
            Self::Adaptive => "adaptive",
        }
    }
}

/// Writes codes into a byte stream, most significant bit first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HuffmanWriter {
    storage: Vec<u8>,
    holding: u32,
    held: u8,
}

impl HuffmanWriter {
    pub fn new() -> Self {
        Self { storage: Vec::new(), holding: 0, held: 0 }
    }

    pub fn write(&mut self, bits: u16, length: u8) {
        self.holding = (self.holding << length) | (bits as u32 & ((1 << length) - 1));
        self.held += length;
        while self.held >= 8 {
            self.held -= 8;
            self.storage.push((self.holding >> self.held) as u8);
        }
    }

    /// Pads the last byte with zero bits and returns the stream.
    pub fn finish(mut self) -> Vec<u8> {
        if self.held != 0 {
            let padding = 8 - self.held;
            self.write(0, padding);
        }
        self.storage
    }

    pub fn len(&self) -> usize {
        self.storage.len()
    }

    pub fn is_empty(&self) -> bool {
        self.storage.is_empty() && self.held == 0
    }
}

impl Default for HuffmanWriter {
    fn default() -> Self {
        Self::new()
    }
}

/// Reads codes out of a byte stream, most significant bit first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HuffmanReader<'a> {
    storage: &'a [u8],
    position: usize,
}

impl<'a> HuffmanReader<'a> {
    pub fn new(storage: &'a [u8]) -> Self {
        Self { storage, position: 0 }
    }

    pub fn bit(&mut self) -> Option<u16> {
        let byte = self.storage.get(self.position / 8)?;
        let bit = (byte >> (7 - self.position % 8)) & 1;
        self.position += 1;
        Some(bit as u16)
    }

    /// Reads one symbol, following the canonical codes of `tree`.
    pub fn symbol(&mut self, tree: &HuffmanTree) -> Result<usize, HuffmanError> {
        tree.walk(|| self.bit().ok_or(HuffmanError::Truncated))?.ok_or(HuffmanError::Symbol)
    }

    pub fn position(&self) -> usize {
        self.position
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HuffmanTree {
    lengths: Vec<u8>,
    codes: Vec<u16>,
    counts: [u16; Huffman::MAXIMUM_LENGTH as usize + 1],
    symbols: Vec<u16>,
    maximum: u8,
}

impl HuffmanTree {
    /// The code lengths a set of frequencies asks for, none longer than `maximum_length`.
    pub fn from_frequencies(frequencies: &[u32], maximum_length: u8) -> Result<Self, HuffmanError> {
        let active = frequencies.iter().filter(|frequency| **frequency > 0).count();
        if active == 0 || maximum_length == 0 || maximum_length > 15 {
            return Err(HuffmanError::Lengths);
        }
        if active > 1 << maximum_length {
            return Err(HuffmanError::Lengths);
        }
        if active == 1 {
            let mut lengths = vec![0; frequencies.len()];
            lengths[frequencies.iter().position(|frequency| *frequency > 0).unwrap_or(0)] = 1;
            return Self::from_lengths(&lengths);
        }
        let mut lengths = Self::depths(frequencies);
        Self::limit(&mut lengths, frequencies, maximum_length);
        Self::from_lengths(&lengths)
    }

    /// The unlimited Huffman depth of every symbol, zero for the unused ones.
    pub fn depths(frequencies: &[u32]) -> Vec<u8> {
        let mut leaves: Vec<(u64, usize)> = frequencies.iter().enumerate().filter(|(_, frequency)| **frequency > 0).map(|(symbol, frequency)| (*frequency as u64, symbol)).collect();
        leaves.sort_unstable();
        let mut parents: Vec<usize> = vec![usize::MAX; leaves.len() * 2];
        let mut internal: Vec<(u64, usize, usize)> = Vec::with_capacity(leaves.len());
        let (mut leaf, mut node) = (0, 0);
        while (leaves.len() - leaf) + (internal.len() - node) > 1 {
            let mut taken = [0; 2];
            for slot in taken.iter_mut() {
                let from_leaf = leaf < leaves.len() && (node >= internal.len() || leaves[leaf].0 <= internal[node].0);
                match from_leaf {
                    true => {
                        *slot = leaf;
                        leaf += 1;
                    }
                    false => {
                        *slot = leaves.len() + node;
                        node += 1;
                    }
                }
            }
            let weight = Self::weight(&leaves, &internal, taken[0]) + Self::weight(&leaves, &internal, taken[1]);
            let index = leaves.len() + internal.len();
            internal.push((weight, taken[0], taken[1]));
            parents[taken[0]] = index;
            parents[taken[1]] = index;
        }
        let mut depths = vec![0; frequencies.len()];
        for (index, (_, symbol)) in leaves.iter().enumerate() {
            let mut depth = 0;
            let mut walk = index;
            while parents[walk] != usize::MAX {
                walk = parents[walk];
                depth += 1;
            }
            depths[*symbol] = depth;
        }
        depths
    }

    /// The weight of a node, whichever list it lives in.
    pub fn weight(leaves: &[(u64, usize)], internal: &[(u64, usize, usize)], index: usize) -> u64 {
        match index < leaves.len() {
            true => leaves[index].0,
            false => internal[index - leaves.len()].0,
        }
    }

    /// Pulls every code down to `maximum_length`, lengthening and shortening others to stay complete.
    pub fn limit(lengths: &mut [u8], frequencies: &[u32], maximum_length: u8) {
        if lengths.iter().all(|length| *length <= maximum_length) {
            return;
        }
        for length in lengths.iter_mut().filter(|length| **length > maximum_length) {
            *length = maximum_length;
        }
        let target = 1u64 << maximum_length;
        let mut kraft: u64 = lengths.iter().filter(|length| **length > 0).map(|length| 1u64 << (maximum_length - *length)).sum();
        while kraft > target {
            let candidate = (0..lengths.len()).filter(|symbol| lengths[*symbol] > 0 && lengths[*symbol] < maximum_length).max_by_key(|symbol| (lengths[*symbol], Reverse(frequencies[*symbol])));
            match candidate {
                Some(symbol) => {
                    kraft -= 1 << (maximum_length - lengths[symbol] - 1);
                    lengths[symbol] += 1;
                }
                None => break,
            }
        }
        while kraft < target {
            let candidate = (0..lengths.len()).filter(|symbol| lengths[*symbol] > 1 && kraft + (1 << (maximum_length - lengths[*symbol])) <= target).max_by_key(|symbol| (frequencies[*symbol], Reverse(lengths[*symbol])));
            match candidate {
                Some(symbol) => {
                    kraft += 1 << (maximum_length - lengths[symbol]);
                    lengths[symbol] -= 1;
                }
                None => break,
            }
        }
    }

    /// The canonical codes a set of lengths describes.
    pub fn from_lengths(lengths: &[u8]) -> Result<Self, HuffmanError> {
        let maximum = lengths.iter().copied().max().unwrap_or(0);
        if maximum > Huffman::MAXIMUM_LENGTH {
            return Err(HuffmanError::Lengths);
        }
        let mut counts = [0u16; Huffman::MAXIMUM_LENGTH as usize + 1];
        for length in lengths.iter().filter(|length| **length > 0) {
            counts[*length as usize] += 1;
        }
        let mut left = 1i64;
        for length in 1..=maximum as usize {
            left = (left << 1) - counts[length] as i64;
            if left < 0 {
                return Err(HuffmanError::Lengths);
            }
        }
        let (mut next, mut offsets) = ([0u16; Huffman::MAXIMUM_LENGTH as usize + 1], [0u16; Huffman::MAXIMUM_LENGTH as usize + 1]);
        let (mut code, mut offset) = (0u32, 0u16);
        for length in 1..=maximum as usize {
            code = (code + counts[length - 1] as u32) << 1;
            (next[length], offsets[length]) = (code as u16, offset);
            offset += counts[length];
        }
        let mut codes = vec![0u16; lengths.len()];
        let mut symbols = vec![0u16; offset as usize];
        for (symbol, length) in lengths.iter().enumerate().filter(|(_, length)| **length > 0) {
            let length = *length as usize;
            codes[symbol] = next[length];
            symbols[offsets[length] as usize] = symbol as u16;
            (next[length], offsets[length]) = (next[length] + 1, offsets[length] + 1);
        }
        Ok(Self { lengths: lengths.to_vec(), codes, counts, symbols, maximum })
    }

    pub fn lengths(&self) -> &[u8] {
        &self.lengths
    }

    pub fn codes(&self) -> &[u16] {
        &self.codes
    }

    pub fn encode(&self, symbol: usize) -> Option<(u16, u8)> {
        match self.lengths.get(symbol) {
            Some(0) | None => None,
            Some(length) => Some((self.codes[symbol], *length)),
        }
    }

    /// The longest code this tree carries.
    pub fn maximum(&self) -> u8 {
        self.maximum
    }

    pub fn decode(&self, bits: u16, length: u8) -> Option<usize> {
        let (mut first, mut index) = (0u32, 0usize);
        for entry in 1..=length as usize {
            let count = self.counts.get(entry).copied().unwrap_or(0) as u32;
            if entry == length as usize {
                return match (bits as u32).wrapping_sub(first) < count {
                    true => Some(self.symbols[index + (bits as u32 - first) as usize] as usize),
                    false => None,
                };
            }
            index += count as usize;
            first = (first + count) << 1;
        }
        None
    }

    /// Reads one symbol, taking the code one bit at a time, most significant first.
    ///
    /// Returns `None` once the longest code this tree carries has passed without naming a symbol.
    pub fn walk<E>(&self, mut bit: impl FnMut() -> Result<u16, E>) -> Result<Option<usize>, E> {
        let (mut code, mut first, mut index) = (0u32, 0u32, 0usize);
        for length in 1..=self.maximum as usize {
            code |= bit()? as u32;
            let count = self.counts[length] as u32;
            if code.wrapping_sub(first) < count {
                return Ok(Some(self.symbols[index + (code - first) as usize] as usize));
            }
            index += count as usize;
            first = (first + count) << 1;
            code <<= 1;
        }
        Ok(None)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticHuffman {
    tree: HuffmanTree,
    limit: Option<usize>,
}

impl StaticHuffman {
    pub fn new(tree: HuffmanTree) -> Self {
        Self { tree, limit: None }
    }

    /// The code the byte frequencies of `data` ask for, with the closing symbol counted once.
    pub fn from_data(data: &[u8]) -> Result<Self, HuffmanError> {
        let mut frequencies = vec![0u32; Huffman::SYMBOLS];
        for byte in data {
            frequencies[*byte as usize] += 1;
        }
        frequencies[Huffman::END] = 1;
        Ok(Self::new(HuffmanTree::from_frequencies(&frequencies, Huffman::MAXIMUM_LENGTH)?))
    }

    pub fn with_limit(self, limit: Option<usize>) -> Self {
        Self { limit, ..self }
    }

    pub fn tree(&self) -> &HuffmanTree {
        &self.tree
    }

    /// The code lengths, one byte each, that `decode` needs to rebuild the tree.
    pub fn header(&self) -> Vec<u8> {
        self.tree.lengths().to_vec()
    }

    pub fn encode(&self, data: &[u8]) -> Result<Vec<u8>, HuffmanError> {
        let mut writer = HuffmanWriter::new();
        for byte in data {
            let (code, length) = self.tree.encode(*byte as usize).ok_or(HuffmanError::Symbol)?;
            writer.write(code, length);
        }
        let (code, length) = self.tree.encode(Huffman::END).ok_or(HuffmanError::Symbol)?;
        writer.write(code, length);
        Ok(writer.finish())
    }

    pub fn decode(&self, data: &[u8]) -> Result<Vec<u8>, HuffmanError> {
        let mut reader = HuffmanReader::new(data);
        let mut output = Vec::new();
        loop {
            match reader.symbol(&self.tree)? {
                Huffman::END => return Ok(output),
                symbol if symbol < Huffman::END => {
                    if self.limit.is_some_and(|limit| output.len() >= limit) {
                        return Err(HuffmanError::Limit);
                    }
                    output.push(symbol as u8);
                }
                _ => return Err(HuffmanError::Symbol),
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdaptiveHuffman {
    tree: HuffmanTree,
    frequencies: Vec<u32>,
    limit: Option<usize>,
}

impl AdaptiveHuffman {
    pub fn new() -> Self {
        let frequencies = vec![1; Huffman::SYMBOLS];
        let tree = HuffmanTree::from_frequencies(&frequencies, Huffman::MAXIMUM_LENGTH).unwrap_or_else(|_| HuffmanTree { lengths: Vec::new(), codes: Vec::new(), counts: [0; Huffman::MAXIMUM_LENGTH as usize + 1], symbols: Vec::new(), maximum: 0 });
        Self { tree, frequencies, limit: None }
    }

    pub fn with_limit(self, limit: Option<usize>) -> Self {
        Self { limit, ..self }
    }

    pub fn tree(&self) -> &HuffmanTree {
        &self.tree
    }

    /// Counts one symbol and rebuilds the code both sides now share.
    pub fn observe(&mut self, symbol: usize) -> Result<(), HuffmanError> {
        self.frequencies[symbol] += 1;
        self.tree = HuffmanTree::from_frequencies(&self.frequencies, Huffman::MAXIMUM_LENGTH)?;
        Ok(())
    }

    pub fn encode(&mut self, data: &[u8]) -> Result<Vec<u8>, HuffmanError> {
        let mut writer = HuffmanWriter::new();
        for byte in data {
            let (code, length) = self.tree.encode(*byte as usize).ok_or(HuffmanError::Symbol)?;
            writer.write(code, length);
            self.observe(*byte as usize)?;
        }
        let (code, length) = self.tree.encode(Huffman::END).ok_or(HuffmanError::Symbol)?;
        writer.write(code, length);
        Ok(writer.finish())
    }

    pub fn decode(&mut self, data: &[u8]) -> Result<Vec<u8>, HuffmanError> {
        let mut reader = HuffmanReader::new(data);
        let mut output = Vec::new();
        loop {
            match reader.symbol(&self.tree)? {
                Huffman::END => return Ok(output),
                symbol if symbol < Huffman::END => {
                    if self.limit.is_some_and(|limit| output.len() >= limit) {
                        return Err(HuffmanError::Limit);
                    }
                    output.push(symbol as u8);
                    self.observe(symbol)?;
                }
                _ => return Err(HuffmanError::Symbol),
            }
        }
    }

    pub fn reset(&mut self) {
        *self = Self::new().with_limit(self.limit);
    }
}

impl Default for AdaptiveHuffman {
    fn default() -> Self {
        Self::new()
    }
}

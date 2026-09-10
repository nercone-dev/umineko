use alloc::vec::Vec;
use crate::errors::HuffmanError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Huffman {
    Static,
    Adaptive,
}

impl Huffman {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Static => "static",
            Self::Adaptive => "adaptive",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HuffmanTree {
    lengths: Vec<u8>,
    codes: Vec<u16>,
}

impl HuffmanTree {
        pub fn from_frequencies(frequencies: &[u32], maximum_length: u8) -> Result<Self, HuffmanError> {
        todo!()
    }

        pub fn from_lengths(lengths: &[u8]) -> Result<Self, HuffmanError> {
        todo!()
    }

    pub fn lengths(&self) -> &[u8] {
        todo!()
    }

    pub fn encode(&self, symbol: usize) -> Option<(u16, u8)> {
        todo!()
    }

    pub fn decode(&self, bits: u16, length: u8) -> Option<usize> {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticHuffman {
    tree: HuffmanTree,
    limit: Option<usize>,
}

impl StaticHuffman {
    pub fn new(tree: HuffmanTree) -> Self {
        todo!()
    }

    pub fn encode(&self, data: &[u8]) -> Result<Vec<u8>, HuffmanError> {
        todo!()
    }

    pub fn decode(&self, data: &[u8]) -> Result<Vec<u8>, HuffmanError> {
        todo!()
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
        todo!()
    }

    pub fn encode(&mut self, data: &[u8]) -> Result<Vec<u8>, HuffmanError> {
        todo!()
    }

    pub fn decode(&mut self, data: &[u8]) -> Result<Vec<u8>, HuffmanError> {
        todo!()
    }

    pub fn reset(&mut self) {
        todo!()
    }
}

impl Default for AdaptiveHuffman {
    fn default() -> Self {
        Self::new()
    }
}

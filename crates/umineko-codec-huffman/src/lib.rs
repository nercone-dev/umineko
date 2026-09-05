//! Huffman coding.

#![no_std]

extern crate alloc;

pub mod errors;
pub mod huffman;

pub use errors::{HuffmanError};
pub use huffman::{AdaptiveHuffman, Huffman, HuffmanReader, HuffmanTree, HuffmanWriter, StaticHuffman};

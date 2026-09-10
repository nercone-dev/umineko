use alloc::vec::Vec;

use crate::bytes::Bytes;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Buffer {
    storage: Vec<u8>,
    offset: usize,
    limit: Option<usize>,
}

impl Buffer {
    pub fn new() -> Self {
        todo!()
    }

    pub fn with_limit(limit: usize) -> Self {
        todo!()
    }

    pub fn as_slice(&self) -> &[u8] {
        todo!()
    }

    pub fn extend(&mut self, data: &[u8]) -> Result<(), BufferError> {
        todo!()
    }

    pub fn consume(&mut self, length: usize) -> Option<Bytes> {
        todo!()
    }

    pub fn consume_until(&mut self, delimiter: &[u8]) -> Option<Bytes> {
        todo!()
    }

    pub fn peek(&self, length: usize) -> Option<&[u8]> {
        todo!()
    }

    pub fn compact(&mut self) {
        todo!()
    }

    pub fn clear(&mut self) {
        todo!()
    }

    pub fn len(&self) -> usize {
        self.storage.len() - self.offset
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for Buffer {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BufferError {
        Overflow,
}

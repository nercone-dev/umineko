use alloc::vec::Vec;
use core::fmt;

use crate::bytes::Bytes;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Buffer {
    storage: Vec<u8>,
    offset: usize,
    limit: Option<usize>,
}

impl Buffer {
    pub fn new() -> Self {
        Self { storage: Vec::new(), offset: 0, limit: None }
    }

    pub fn with_limit(limit: usize) -> Self {
        Self { storage: Vec::new(), offset: 0, limit: Some(limit) }
    }

    pub fn limit(&self) -> Option<usize> {
        self.limit
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.storage[self.offset..]
    }

    /// The point past which the read bytes are worth reclaiming, which one compaction pays for.
    pub const COMPACTION: usize = 4096;

    pub fn extend(&mut self, data: &[u8]) -> Result<(), BufferError> {
        match self.limit {
            Some(limit) if self.len().checked_add(data.len()).is_none_or(|length| length > limit) => Err(BufferError::Overflow),
            _ => {
                if self.offset >= Self::COMPACTION && self.offset >= self.len() {
                    self.compact();
                }
                self.storage.extend_from_slice(data);
                Ok(())
            }
        }
    }

    pub fn consume(&mut self, length: usize) -> Option<Bytes> {
        match self.len() >= length {
            true => {
                let consumed = Bytes::copy_from_slice(&self.storage[self.offset..self.offset + length]);
                self.advance(length);
                Some(consumed)
            }
            false => None,
        }
    }

    /// Takes everything the buffer holds, leaving it empty.
    pub fn take(&mut self) -> Bytes {
        let taken = Bytes::copy_from_slice(self.as_slice());
        self.clear();
        taken
    }

    pub fn consume_until(&mut self, delimiter: &[u8]) -> Option<Bytes> {
        let position = self.find(delimiter)?;
        let consumed = Bytes::copy_from_slice(&self.storage[self.offset..self.offset + position]);
        self.advance(position + delimiter.len());
        Some(consumed)
    }

    pub fn find(&self, delimiter: &[u8]) -> Option<usize> {
        let data = self.as_slice();
        let (first, rest) = delimiter.split_first()?;
        if delimiter.len() > data.len() {
            return None;
        }
        let mut position = 0;
        while let Some(step) = data[position..data.len() - rest.len()].iter().position(|byte| byte == first) {
            position += step;
            if &data[position + 1..position + 1 + rest.len()] == rest {
                return Some(position);
            }
            position += 1;
        }
        None
    }

    pub fn peek(&self, length: usize) -> Option<&[u8]> {
        match self.len() >= length {
            true => Some(&self.storage[self.offset..self.offset + length]),
            false => None,
        }
    }

    pub fn advance(&mut self, length: usize) -> usize {
        let advanced = length.min(self.len());
        self.offset += advanced;
        if self.offset == self.storage.len() {
            self.clear();
        }
        advanced
    }

    pub fn compact(&mut self) {
        self.storage.copy_within(self.offset.., 0);
        self.storage.truncate(self.storage.len() - self.offset);
        self.offset = 0;
    }

    pub fn clear(&mut self) {
        self.storage.clear();
        self.offset = 0;
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
    /// The buffer would grow past its limit.
    Overflow,
}

impl fmt::Display for BufferError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Overflow => f.write_str("buffer overflow"),
        }
    }
}

impl core::error::Error for BufferError {}

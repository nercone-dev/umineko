use alloc::vec::Vec;
use core::fmt;
use crate::errors::IMAPError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IMAPSequence {
    Number(u32),
    Range { from: u32, to: u32 },
    Last,
    RangeToLast(u32),
}

impl IMAPSequence {
    pub fn contains(&self, number: u32, last: u32) -> bool {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IMAPSequenceSet(Vec<IMAPSequence>);

impl IMAPSequenceSet {
    pub fn new() -> Self {
        todo!()
    }

    pub fn parse(text: &str) -> Result<Self, IMAPError> {
        todo!()
    }

    pub fn push(&mut self, sequence: IMAPSequence) {
        todo!()
    }

    pub fn contains(&self, number: u32, last: u32) -> bool {
        todo!()
    }

    pub fn expand(&self, last: u32) -> Vec<u32> {
        todo!()
    }

    pub fn normalize(&self) -> Self {
        todo!()
    }

    pub fn len(&self) -> usize {
        todo!()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for IMAPSequenceSet {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for IMAPSequenceSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

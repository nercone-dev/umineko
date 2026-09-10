use alloc::vec::Vec;
use crate::errors::IMAPError;
use crate::helpers::sequence::IMAPSequenceSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct IMAPModSequence(pub u64);

impl IMAPModSequence {
    pub const ZERO: Self = Self(0);

    pub fn after(&self, other: Self) -> bool {
        self.0 > other.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IMAPCondStore {
    highest: IMAPModSequence,
    uid_validity: u32,
}

impl IMAPCondStore {
    pub fn new(uid_validity: u32) -> Self {
        todo!()
    }

    pub fn highest(&self) -> IMAPModSequence {
        self.highest
    }

    pub fn changed_since(&self, since: IMAPModSequence) -> IMAPSequenceSet {
        todo!()
    }

    pub fn vanished(&self, since: IMAPModSequence) -> Vec<u32> {
        todo!()
    }

    pub fn validate(&self, uid_validity: u32) -> Result<(), IMAPError> {
        todo!()
    }

    pub fn update(&mut self, sequence: IMAPModSequence) {
        todo!()
    }
}

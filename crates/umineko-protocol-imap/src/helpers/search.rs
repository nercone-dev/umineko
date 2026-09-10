use alloc::{string::String, vec::Vec};
use crate::errors::IMAPError;
use crate::types::IMAPFlag;
use crate::helpers::sequence::IMAPSequenceSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IMAPSearchKey {
    All,
    Sequence(IMAPSequenceSet),
    Uid(IMAPSequenceSet),
    Flag(IMAPFlag),
    NotFlag(IMAPFlag),
    From(String),
    To(String),
    Cc(String),
    Subject(String),
    Body(String),
    Text(String),
    Header { name: String, value: String },
    Since(String),
    Before(String),
    On(String),
    Larger(u64),
    Smaller(u64),
    And(Vec<IMAPSearchKey>),
    Or(Vec<IMAPSearchKey>),
    Not(alloc::boxed::Box<IMAPSearchKey>),
}

impl IMAPSearchKey {
    pub fn encode(&self) -> Result<Vec<u8>, IMAPError> {
        todo!()
    }

    pub fn decode(data: &[u8]) -> Result<(Self, usize), IMAPError> {
        todo!()
    }

    pub fn depth(&self) -> usize {
        todo!()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IMAPSortKey {
    Arrival,
    Date,
    From,
    Subject,
    Size,
    To,
    Cc,
}

impl IMAPSortKey {
    pub fn as_str(&self) -> &'static str {
        todo!()
    }
}

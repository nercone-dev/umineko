use alloc::{string::String, vec::Vec};
use crate::errors::IMAPError;
use crate::types::IMAPLimits;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IMAPLiteral {
    pub data: Vec<u8>,
    pub non_synchronizing: bool,
}

impl IMAPLiteral {
    pub fn encode(&self) -> Result<Vec<u8>, IMAPError> {
        todo!()
    }

    pub fn decode_header(data: &[u8], limits: IMAPLimits) -> Result<(u64, bool, usize), IMAPError> {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IMAPString {
    Quoted(String),
    Literal(IMAPLiteral),
    Atom(String),
}

impl IMAPString {
    pub fn new(text: &str) -> Self {
        todo!()
    }

    pub fn as_str(&self) -> Option<&str> {
        todo!()
    }

    pub fn encode(&self) -> Result<Vec<u8>, IMAPError> {
        todo!()
    }

    pub fn decode(data: &[u8], limits: IMAPLimits) -> Result<(Self, usize), IMAPError> {
        todo!()
    }
}

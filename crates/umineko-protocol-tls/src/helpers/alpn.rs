use alloc::{string::String, vec::Vec};
use crate::errors::TLSError;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TLSApplicationProtocol(String);

impl TLSApplicationProtocol {
    pub const MAXIMUM_LENGTH: usize = 255;

    pub fn new(name: &str) -> Result<Self, TLSError> {
        todo!()
    }

    pub fn as_str(&self) -> &str {
        todo!()
    }

    pub fn select(offered: &[Self], supported: &[Self]) -> Option<Self> {
        todo!()
    }

    pub fn encode(protocols: &[Self]) -> Result<Vec<u8>, TLSError> {
        todo!()
    }

    pub fn decode(data: &[u8]) -> Result<Vec<Self>, TLSError> {
        todo!()
    }
}

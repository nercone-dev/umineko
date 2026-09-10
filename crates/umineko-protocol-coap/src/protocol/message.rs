use alloc::vec::Vec;
use crate::errors::CoAPError;
use crate::types::{CoAPVersion, CoAPType, CoAPCode, CoAPOption, CoAPLimits};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CoAPToken(Vec<u8>);

impl CoAPToken {
    pub const MAXIMUM_LENGTH: usize = 8;

    pub fn new(data: &[u8]) -> Result<Self, CoAPError> {
        todo!()
    }

    pub fn as_slice(&self) -> &[u8] {
        todo!()
    }

    pub fn is_empty(&self) -> bool {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoAPMessage {
    pub version: CoAPVersion,
    pub kind: CoAPType,
    pub code: CoAPCode,
    pub id: u16,
    pub token: CoAPToken,
    pub options: Vec<CoAPOption>,
    pub payload: Vec<u8>,
}

impl CoAPMessage {
    pub const HEADER_SIZE: usize = 4;
    pub const PAYLOAD_MARKER: u8 = 0xFF;

    pub fn request(code: CoAPCode, id: u16, token: CoAPToken) -> Self {
        todo!()
    }

    pub fn respond(&self, code: CoAPCode) -> Self {
        todo!()
    }

    pub fn acknowledge(&self) -> Self {
        todo!()
    }

    pub fn reset(&self) -> Self {
        todo!()
    }

    pub fn matches(&self, request: &Self) -> bool {
        todo!()
    }

    pub fn option(&self, kind: u16) -> Option<&CoAPOption> {
        todo!()
    }

    pub fn validate(&self, limits: CoAPLimits) -> Result<(), CoAPError> {
        todo!()
    }

    pub fn encode(&self, limits: CoAPLimits) -> Result<Vec<u8>, CoAPError> {
        todo!()
    }

    pub fn decode(data: &[u8], limits: CoAPLimits) -> Result<Self, CoAPError> {
        todo!()
    }
}

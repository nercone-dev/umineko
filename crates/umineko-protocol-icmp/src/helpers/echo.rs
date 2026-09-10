use alloc::vec::Vec;
use crate::errors::ICMPError;
use crate::types::ICMPVersion;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ICMPEchoRequest {
    pub identifier: u16,
    pub sequence: u16,
    pub payload: Vec<u8>,
}

impl ICMPEchoRequest {
    pub fn new(identifier: u16, sequence: u16, payload: Vec<u8>) -> Self {
        todo!()
    }

    pub fn encode(&self, version: ICMPVersion) -> Result<Vec<u8>, ICMPError> {
        todo!()
    }

    pub fn decode(version: ICMPVersion, data: &[u8]) -> Result<Self, ICMPError> {
        todo!()
    }

    pub fn reply(&self) -> ICMPEchoReply {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ICMPEchoReply {
    pub identifier: u16,
    pub sequence: u16,
    pub payload: Vec<u8>,
}

impl ICMPEchoReply {
    pub fn encode(&self, version: ICMPVersion) -> Result<Vec<u8>, ICMPError> {
        todo!()
    }

    pub fn decode(version: ICMPVersion, data: &[u8]) -> Result<Self, ICMPError> {
        todo!()
    }

    pub fn matches(&self, request: &ICMPEchoRequest) -> bool {
        todo!()
    }
}

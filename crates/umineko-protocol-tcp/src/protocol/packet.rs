use alloc::vec::Vec;
use crate::errors::TCPError;
use crate::types::{TCPPort, TCPFlags, TCPOption};

use umineko_protocol_ip::IPAddress;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TCPHeader {
    pub source: TCPPort,
    pub destination: TCPPort,
    pub sequence: u32,
    pub acknowledgement: u32,
    pub flags: TCPFlags,
    pub window: u16,
    pub urgent: u16,
    pub options: Vec<TCPOption>,
}

impl TCPHeader {
    pub const MINIMUM_SIZE: usize = 20;
    pub const MAXIMUM_SIZE: usize = 60;

    pub fn len(&self) -> usize {
        todo!()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn encode(&self, source: IPAddress, destination: IPAddress, payload: &[u8]) -> Result<Vec<u8>, TCPError> {
        todo!()
    }

    pub fn decode(data: &[u8]) -> Result<(Self, usize), TCPError> {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TCPPacket {
    pub header: TCPHeader,
    pub payload: Vec<u8>,
}

impl TCPPacket {
    pub fn sequence_length(&self) -> u32 {
        todo!()
    }

    pub fn encode(&self, source: IPAddress, destination: IPAddress) -> Result<Vec<u8>, TCPError> {
        todo!()
    }

    pub fn decode(data: &[u8], source: IPAddress, destination: IPAddress) -> Result<Self, TCPError> {
        todo!()
    }
}

use alloc::vec::Vec;
use crate::errors::UDPError;
use crate::types::UDPPort;

use umineko_protocol_ip::IPAddress;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UDPHeader {
    pub source: UDPPort,
    pub destination: UDPPort,
    pub length: u16,
}

impl UDPHeader {
    pub const SIZE: usize = 8;

    pub fn encode(&self, source: IPAddress, destination: IPAddress, payload: &[u8]) -> Result<Vec<u8>, UDPError> {
        todo!()
    }

    pub fn decode(data: &[u8]) -> Result<(Self, usize), UDPError> {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UDPPacket {
    pub header: UDPHeader,
    pub payload: Vec<u8>,
}

impl UDPPacket {
    pub fn encode(&self, source: IPAddress, destination: IPAddress) -> Result<Vec<u8>, UDPError> {
        todo!()
    }

    pub fn decode(data: &[u8], source: IPAddress, destination: IPAddress) -> Result<Self, UDPError> {
        todo!()
    }
}

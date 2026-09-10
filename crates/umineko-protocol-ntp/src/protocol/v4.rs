use crate::errors::NTPError;
use crate::types::{NTPVersion, NTPLimits};
use crate::protocol::base::NTPPacket;

#[derive(Debug)]
pub struct NTPV4Connection {
    limits: NTPLimits,
}

impl NTPV4Connection {
    pub const VERSION: NTPVersion = NTPVersion::V4;

    pub async fn connect(server: &str, port: u16, limits: NTPLimits) -> Result<Self, NTPError> {
        todo!()
    }

    pub fn version(&self) -> NTPVersion {
        Self::VERSION
    }

    pub fn limits(&self) -> NTPLimits {
        self.limits
    }

    pub async fn send(&mut self, packet: &NTPPacket) -> Result<(), NTPError> {
        todo!()
    }

    pub async fn receive(&mut self) -> Result<NTPPacket, NTPError> {
        todo!()
    }

    pub async fn query(&mut self, packet: &NTPPacket) -> Result<NTPPacket, NTPError> {
        todo!()
    }

    pub async fn reply(&mut self, packet: &NTPPacket) -> Result<(), NTPError> {
        todo!()
    }

    pub async fn close(&mut self) -> Result<(), NTPError> {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NTPExtension {
    Authentication(alloc::vec::Vec<u8>),
    KeyEstablishment(alloc::vec::Vec<u8>),
    UniqueIdentifier(alloc::vec::Vec<u8>),
    Unknown { kind: u16, data: alloc::vec::Vec<u8> },
}

impl NTPExtension {
    pub fn kind(&self) -> u16 {
        todo!()
    }

    pub fn encode(&self) -> Result<alloc::vec::Vec<u8>, NTPError> {
        todo!()
    }

    pub fn decode(data: &[u8]) -> Result<(Self, usize), NTPError> {
        todo!()
    }
}

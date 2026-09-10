use alloc::vec::Vec;
use crate::errors::QUICError;
use crate::types::{QUICVersion, QUICConnectionID, QUICLimits};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QUICPacketType {
    Initial,
    ZeroRTT,
    Handshake,
    Retry,
    OneRTT,
    VersionNegotiation,
}

impl QUICPacketType {
    pub fn long_header(&self) -> bool {
        !matches!(self, Self::OneRTT)
    }

    pub fn number(&self, version: QUICVersion) -> Option<u8> {
        todo!()
    }

    pub fn from_number(version: QUICVersion, number: u8) -> Option<Self> {
        todo!()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct QUICPacketNumber(pub u64);

impl QUICPacketNumber {
    pub fn encoded_len(&self, largest_acknowledged: Option<Self>) -> usize {
        todo!()
    }

    pub fn decode(truncated: u64, length: usize, largest: Self) -> Self {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QUICPacket {
    pub kind: QUICPacketType,
    pub version: QUICVersion,
    pub source: Option<QUICConnectionID>,
    pub destination: QUICConnectionID,
    pub number: Option<QUICPacketNumber>,
    pub token: Option<Vec<u8>>,
    pub payload: Vec<u8>,
}

impl QUICPacket {
    pub const MINIMUM_INITIAL_SIZE: usize = 1200;

    pub fn encode(&self, limits: QUICLimits) -> Result<Vec<u8>, QUICError> {
        todo!()
    }

    pub fn decode(data: &[u8], limits: QUICLimits) -> Result<(Self, usize), QUICError> {
        todo!()
    }

    pub fn decode_all(data: &[u8], limits: QUICLimits) -> Result<Vec<Self>, QUICError> {
        todo!()
    }
}

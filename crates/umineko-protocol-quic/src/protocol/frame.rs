use alloc::vec::Vec;
use crate::errors::{QUICError, QUICTransportError};
use crate::types::{QUICConnectionID, QUICStreamID};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QUICFrameType {
    Padding,
    Ping,
    Ack,
    ResetStream,
    StopSending,
    Crypto,
    NewToken,
    Stream,
    MaxData,
    MaxStreamData,
    MaxStreams,
    DataBlocked,
    StreamDataBlocked,
    StreamsBlocked,
    NewConnectionID,
    RetireConnectionID,
    PathChallenge,
    PathResponse,
    ConnectionClose,
    HandshakeDone,
    Unknown(u64),
}

impl QUICFrameType {
    pub fn retransmittable(&self) -> bool {
        !matches!(self, Self::Padding | Self::Ack)
    }

    pub fn congestion_controlled(&self) -> bool {
        !matches!(self, Self::Ack)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QUICFrame {
    Padding(usize),
    Ping,
    Ack { largest: u64, delay: u64, ranges: Vec<(u64, u64)> },
    ResetStream { stream: QUICStreamID, error: u64, final_size: u64 },
    StopSending { stream: QUICStreamID, error: u64 },
    Crypto { offset: u64, data: Vec<u8> },
    NewToken(Vec<u8>),
    Stream { stream: QUICStreamID, offset: u64, fin: bool, data: Vec<u8> },
    MaxData(u64),
    MaxStreamData { stream: QUICStreamID, maximum: u64 },
    MaxStreams { bidirectional: bool, maximum: u64 },
    DataBlocked(u64),
    StreamDataBlocked { stream: QUICStreamID, limit: u64 },
    StreamsBlocked { bidirectional: bool, limit: u64 },
    NewConnectionID { sequence: u64, retire: u64, id: QUICConnectionID, token: [u8; 16] },
    RetireConnectionID(u64),
    PathChallenge([u8; 8]),
    PathResponse([u8; 8]),
    ConnectionClose { error: QUICTransportError, frame: Option<QUICFrameType>, reason: Vec<u8> },
    HandshakeDone,
}

impl QUICFrame {
    pub fn kind(&self) -> QUICFrameType {
        todo!()
    }

    pub fn encode(&self) -> Result<Vec<u8>, QUICError> {
        todo!()
    }

    pub fn decode(data: &[u8]) -> Result<(Self, usize), QUICError> {
        todo!()
    }

    pub fn decode_all(data: &[u8]) -> Result<Vec<Self>, QUICError> {
        todo!()
    }
}

use alloc::{string::String, vec::Vec};
use crate::errors::HTTPError;
use crate::types::{HTTPMessage, HTTPStreamID, HTTPLimits};

use umineko_helpers::Bytes;

pub const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WSOpcode {
    Continuation,
    Text,
    Binary,
    Close,
    Ping,
    Pong,
    Unknown(u8),
}

impl WSOpcode {
    pub fn number(&self) -> u8 {
        todo!()
    }

    pub fn from_number(number: u8) -> Self {
        todo!()
    }

    pub fn control(&self) -> bool {
        matches!(self, Self::Close | Self::Ping | Self::Pong)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WSCloseCode {
    Normal,
    GoingAway,
    ProtocolError,
    UnsupportedData,
    InvalidPayload,
    PolicyViolation,
    MessageTooBig,
    MissingExtension,
    InternalError,
    Unknown(u16),
}

impl WSCloseCode {
    pub fn number(&self) -> u16 {
        todo!()
    }

    pub fn from_number(number: u16) -> Self {
        todo!()
    }

    pub fn sendable(&self) -> bool {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WSFrame {
    pub opcode: WSOpcode,
    pub fin: bool,
    pub mask: Option<[u8; 4]>,
    pub payload: Bytes,
}

impl WSFrame {
    pub const MAXIMUM_CONTROL_PAYLOAD_SIZE: usize = 125;

    pub fn encode(&self) -> Result<Vec<u8>, HTTPError> {
        todo!()
    }

    pub fn decode(data: &[u8], limits: HTTPLimits) -> Result<(Self, usize), HTTPError> {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WSMessage {
    Text(String),
    Binary(Bytes),
    Close { code: WSCloseCode, reason: String },
    Ping(Bytes),
    Pong(Bytes),
}

impl WSMessage {
    pub fn opcode(&self) -> WSOpcode {
        todo!()
    }

    pub fn len(&self) -> usize {
        todo!()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn frames(&self, maximum: usize, mask: Option<[u8; 4]>) -> Result<Vec<WSFrame>, HTTPError> {
        todo!()
    }
}

#[derive(Debug)]
pub struct WSConnection {
    stream: HTTPStreamID,
    protocol: Option<String>,
    masked: bool,
    limits: HTTPLimits,
}

impl WSConnection {
    pub fn accept(request: &HTTPMessage) -> Result<HTTPMessage, HTTPError> {
        todo!()
    }

    pub fn verify(request: &HTTPMessage, response: &HTTPMessage) -> Result<(), HTTPError> {
        todo!()
    }

    pub fn protocol(&self) -> Option<&str> {
        todo!()
    }

    pub async fn send(&mut self, message: WSMessage) -> Result<(), HTTPError> {
        todo!()
    }

    pub async fn receive(&mut self) -> Result<WSMessage, HTTPError> {
        todo!()
    }

    pub async fn ping(&mut self) -> Result<f64, HTTPError> {
        todo!()
    }

    pub async fn close(&mut self, code: WSCloseCode, reason: &str) -> Result<(), HTTPError> {
        todo!()
    }
}

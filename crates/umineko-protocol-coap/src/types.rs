use alloc::{string::String, vec::Vec};
use core::fmt;
use crate::errors::CoAPError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CoAPVersion {
    V1,
}

impl CoAPVersion {
    pub fn number(&self) -> u8 {
        match self {
            Self::V1 => 1,
        }
    }

    pub fn from_number(number: u8) -> Option<Self> {
        match number {
            1 => Some(Self::V1),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::V1 => "CoAPv1",
        }
    }
}

impl fmt::Display for CoAPVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CoAPType {
    Confirmable,
    NonConfirmable,
    Acknowledgement,
    Reset,
}

impl CoAPType {
    pub fn number(&self) -> u8 {
        todo!()
    }

    pub fn from_number(number: u8) -> Option<Self> {
        todo!()
    }

    pub fn retransmitted(&self) -> bool {
        matches!(self, Self::Confirmable)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CoAPCode {
    Empty,

    GET,
    POST,
    PUT,
    DELETE,
    FETCH,
    PATCH,

    Created,
    Deleted,
    Valid,
    Changed,
    Content,
    Continue,

    BadRequest,
    Unauthorized,
    BadOption,
    Forbidden,
    NotFound,
    MethodNotAllowed,
    NotAcceptable,
    RequestEntityIncomplete,
    PreconditionFailed,
    RequestEntityTooLarge,
    UnsupportedContentFormat,

    InternalServerError,
    NotImplemented,
    BadGateway,
    ServiceUnavailable,
    GatewayTimeout,
    ProxyingNotSupported,

    Unknown(u8),
}

impl CoAPCode {
    pub fn number(&self) -> u8 {
        todo!()
    }

    pub fn from_number(number: u8) -> Self {
        todo!()
    }

    pub fn request(&self) -> bool {
        todo!()
    }

    pub fn success(&self) -> bool {
        todo!()
    }

    pub fn client_error(&self) -> bool {
        todo!()
    }

    pub fn server_error(&self) -> bool {
        todo!()
    }

    pub fn as_str(&self) -> &'static str {
        todo!()
    }
}

impl fmt::Display for CoAPCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CoAPContentFormat {
    PlainText,
    LinkFormat,
    XML,
    OctetStream,
    EXI,
    JSON,
    CBOR,
    Unknown(u16),
}

impl CoAPContentFormat {
    pub fn number(&self) -> u16 {
        todo!()
    }

    pub fn from_number(number: u16) -> Self {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoAPOption {
    IfMatch(Vec<u8>),
    UriHost(String),
    ETag(Vec<u8>),
    IfNoneMatch,
    UriPort(u16),
    LocationPath(String),
    UriPath(String),
    ContentFormat(CoAPContentFormat),
    MaxAge(u32),
    UriQuery(String),
    Accept(CoAPContentFormat),
    LocationQuery(String),
    ProxyUri(String),
    ProxyScheme(String),
    Observe(u32),
    Block2 { number: u32, more: bool, size: u16 },
    Block1 { number: u32, more: bool, size: u16 },
    Size1(u32),
    Size2(u32),
    Unknown { kind: u16, data: Vec<u8> },
}

impl CoAPOption {
    pub fn kind(&self) -> u16 {
        todo!()
    }

    pub fn critical(&self) -> bool {
        todo!()
    }

    pub fn unsafe_to_forward(&self) -> bool {
        todo!()
    }

    pub fn no_cache_key(&self) -> bool {
        todo!()
    }

    pub fn encode(&self, previous: u16) -> Result<Vec<u8>, CoAPError> {
        todo!()
    }

    pub fn decode(data: &[u8], previous: u16) -> Result<(Self, usize), CoAPError> {
        todo!()
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CoAPLimits {
    pub max_message_size: u16,
    pub max_payload_size: u16,
    pub max_option_count: u8,
    pub max_option_size: u16,
    pub max_token_length: u8,
    pub max_block_size: u16,

    pub max_connection_count: u64,
    pub max_outstanding_count: u16,
    pub max_observation_count: u32,
    pub max_retransmit_count: u8,

    pub acknowledgement_timeout: f64,
    pub acknowledgement_random_factor: f64,
    pub max_processing_delay: f64,
    pub read_timeout: f64,
    pub write_timeout: f64,
}

impl Default for CoAPLimits {
    fn default() -> Self {
        Self {
            max_message_size: 1152,
            max_payload_size: 1024,
            max_option_count: 32,
            max_option_size: 512,
            max_token_length: 8,
            max_block_size: 1024,

            max_connection_count: 1024,
            max_outstanding_count: 1,
            max_observation_count: 4096,
            max_retransmit_count: 4,

            acknowledgement_timeout: 2.0,
            acknowledgement_random_factor: 1.5,
            max_processing_delay: 2.0,
            read_timeout: 30.0,
            write_timeout: 30.0,
        }
    }
}

use alloc::vec::Vec;
use core::fmt;
use crate::errors::QUICError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QUICVersion {
    V1,
    V2,
}

impl QUICVersion {
    pub const NEGOTIATION: u32 = 0x0000_0000;

    pub fn number(&self) -> u32 {
        match self {
            Self::V1 => 0x0000_0001,
            Self::V2 => 0x6b33_43cf,
        }
    }

    pub fn from_number(number: u32) -> Option<Self> {
        match number {
            0x0000_0001 => Some(Self::V1),
            0x6b33_43cf => Some(Self::V2),
            _ => None,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::V1 => "quic",
            Self::V2 => "quicv2",
        }
    }

    pub fn packet_type_number(&self, kind: u8) -> u8 {
        todo!()
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::V1 => "QUICv1",
            Self::V2 => "QUICv2",
        }
    }
}

impl fmt::Display for QUICVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QUICRole {
    Client,
    Server,
}

impl QUICRole {
    pub fn peer(&self) -> Self {
        match self {
            Self::Client => Self::Server,
            Self::Server => Self::Client,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct QUICConnectionID(Vec<u8>);

impl QUICConnectionID {
    pub const MAXIMUM_LENGTH: usize = 20;

    pub fn new(data: &[u8]) -> Result<Self, QUICError> {
        todo!()
    }

    pub fn as_slice(&self) -> &[u8] {
        todo!()
    }

    pub fn len(&self) -> usize {
        todo!()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct QUICStreamID(pub u64);

impl QUICStreamID {
    pub fn client_initiated(&self) -> bool {
        self.0 & 0x01 == 0
    }

    pub fn bidirectional(&self) -> bool {
        self.0 & 0x02 == 0
    }

    pub fn index(&self) -> u64 {
        self.0 >> 2
    }
}

impl fmt::Display for QUICStreamID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QUICTransportParameters {
    pub original_destination_connection_id: Option<QUICConnectionID>,
    pub initial_source_connection_id: Option<QUICConnectionID>,
    pub retry_source_connection_id: Option<QUICConnectionID>,

    pub max_idle_timeout: u64,
    pub max_udp_payload_size: u64,

    pub initial_max_data: u64,
    pub initial_max_stream_data_bidi_local: u64,
    pub initial_max_stream_data_bidi_remote: u64,
    pub initial_max_stream_data_uni: u64,
    pub initial_max_streams_bidi: u64,
    pub initial_max_streams_uni: u64,

    pub ack_delay_exponent: u64,
    pub max_ack_delay: u64,

    pub disable_active_migration: bool,
    pub active_connection_id_limit: u64,

    pub unknown: Vec<(u64, Vec<u8>)>,
}

impl Default for QUICTransportParameters {
    fn default() -> Self {
        todo!()
    }
}

impl QUICTransportParameters {
    pub fn encode(&self) -> Result<Vec<u8>, QUICError> {
        todo!()
    }

    pub fn decode(data: &[u8]) -> Result<Self, QUICError> {
        todo!()
    }

    pub fn validate(&self, limits: &QUICLimits) -> Result<(), QUICError> {
        todo!()
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct QUICLimits {
    pub max_udp_payload_size: u32,
    pub max_packet_size: u32,
    pub max_frame_count: u16,
    pub max_crypto_buffer_size: u32,
    pub max_token_size: u32,

    pub max_connection_count: u64,
    pub max_connection_id_count: u8,
    pub max_stream_count: u64,
    pub max_stream_data_size: u64,
    pub max_connection_data_size: u64,
    pub max_reorder_count: u16,

    pub max_path_probe_count: u8,
    pub max_packets_per_key: u64,

    pub handshake_timeout: f64,
    pub idle_timeout: f64,
    pub read_timeout: f64,
    pub write_timeout: f64,
    pub close_timeout: f64,
}

impl Default for QUICLimits {
    fn default() -> Self {
        Self {
            max_udp_payload_size: 1452,
            max_packet_size: 1452,
            max_frame_count: 256,
            max_crypto_buffer_size: 64 * 1024,
            max_token_size: 512,

            max_connection_count: 1024,
            max_connection_id_count: 8,
            max_stream_count: 128,
            max_stream_data_size: 1024 * 1024,
            max_connection_data_size: 16 * 1024 * 1024,
            max_reorder_count: 1024,

            max_path_probe_count: 3,
            max_packets_per_key: 1 << 23,

            handshake_timeout: 10.0,
            idle_timeout: 30.0,
            read_timeout: 30.0,
            write_timeout: 30.0,
            close_timeout: 3.0,
        }
    }
}

use alloc::string::String;
use core::fmt;
use crate::errors::UDSError;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum UDSPath {
    File(String),
    Abstract(String),
    Unnamed,
}

impl UDSPath {
    pub const MAXIMUM_LENGTH: usize = 108;

    pub fn parse(text: &str) -> Result<Self, UDSError> {
        todo!()
    }

    pub fn as_str(&self) -> Option<&str> {
        todo!()
    }

    pub fn persistent(&self) -> bool {
        matches!(self, Self::File(_))
    }
}

impl fmt::Display for UDSPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UDSType {
    Stream,
    Datagram,
    Seqpacket,
}

impl UDSType {
    pub fn preserves_boundary(&self) -> bool {
        matches!(self, Self::Datagram | Self::Seqpacket)
    }

    pub fn connection_oriented(&self) -> bool {
        matches!(self, Self::Stream | Self::Seqpacket)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Stream => "stream",
            Self::Datagram => "datagram",
            Self::Seqpacket => "seqpacket",
        }
    }
}

impl fmt::Display for UDSType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct UDSLimits {
    pub max_message_size: u32,

    pub max_connection_count: u64,
    pub max_backlog: u32,
    pub max_send_buffer_size: u32,
    pub max_receive_buffer_size: u32,

    pub max_descriptor_count: u16,
    pub max_ancillary_size: u32,

    pub connect_timeout: f64,
    pub read_timeout: f64,
    pub write_timeout: f64,
    pub close_timeout: f64,
}

impl Default for UDSLimits {
    fn default() -> Self {
        Self {
            max_message_size: 256 * 1024,

            max_connection_count: 1024,
            max_backlog: 128,
            max_send_buffer_size: 256 * 1024,
            max_receive_buffer_size: 256 * 1024,

            max_descriptor_count: 16,
            max_ancillary_size: 4 * 1024,

            connect_timeout: 10.0,
            read_timeout: 30.0,
            write_timeout: 30.0,
            close_timeout: 10.0,
        }
    }
}

use alloc::{string::String, vec::Vec};
use core::fmt;
use crate::errors::SOCKSError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SOCKSVersion {
    V4,
    V5,
}

impl SOCKSVersion {
    pub fn number(&self) -> u8 {
        match self {
            Self::V4 => 4,
            Self::V5 => 5,
        }
    }

    pub fn from_number(number: u8) -> Option<Self> {
        match number {
            4 => Some(Self::V4),
            5 => Some(Self::V5),
            _ => None,
        }
    }

    pub fn remote_resolution(&self) -> bool {
        matches!(self, Self::V5)
    }

    pub fn ipv6(&self) -> bool {
        matches!(self, Self::V5)
    }

    pub fn negotiated_authentication(&self) -> bool {
        matches!(self, Self::V5)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::V4 => "SOCKS4",
            Self::V5 => "SOCKS5",
        }
    }
}

impl fmt::Display for SOCKSVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SOCKSCommand {
    Connect,
    Bind,
    Associate,
}

impl SOCKSCommand {
    pub fn number(&self) -> u8 {
        match self {
            Self::Connect => 1,
            Self::Bind => 2,
            Self::Associate => 3,
        }
    }

    pub fn from_number(number: u8) -> Option<Self> {
        todo!()
    }

    pub fn allowed(&self, version: SOCKSVersion) -> bool {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SOCKSAddress {
    IPv4([u8; 4]),
    IPv6([u8; 16]),
    Domain(String),
}

impl SOCKSAddress {
    pub const MAXIMUM_DOMAIN_LENGTH: usize = 255;

    pub fn parse(text: &str) -> Result<Self, SOCKSError> {
        todo!()
    }

    pub fn kind(&self) -> u8 {
        match self {
            Self::IPv4(_) => 1,
            Self::Domain(_) => 3,
            Self::IPv6(_) => 4,
        }
    }

    pub fn allowed(&self, version: SOCKSVersion) -> bool {
        todo!()
    }

    pub fn encode(&self, version: SOCKSVersion) -> Result<Vec<u8>, SOCKSError> {
        todo!()
    }

    pub fn decode(data: &[u8], version: SOCKSVersion) -> Result<(Self, usize), SOCKSError> {
        todo!()
    }
}

impl fmt::Display for SOCKSAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SOCKSReply {
    Succeeded,
    GeneralFailure,
    NotAllowed,
    NetworkUnreachable,
    HostUnreachable,
    ConnectionRefused,
    TimeToLiveExpired,
    CommandNotSupported,
    AddressNotSupported,
    Unknown(u8),
}

impl SOCKSReply {
    pub fn number(&self, version: SOCKSVersion) -> u8 {
        todo!()
    }

    pub fn from_number(version: SOCKSVersion, number: u8) -> Self {
        todo!()
    }

    pub fn success(&self) -> bool {
        matches!(self, Self::Succeeded)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SOCKSLimits {
    pub max_request_size: u16,
    pub max_domain_length: u16,
    pub max_method_count: u8,

    pub max_connection_count: u64,
    pub max_authentication_attempts: u8,
    pub max_datagram_size: u32,

    pub connect_timeout: f64,
    pub handshake_timeout: f64,
    pub read_timeout: f64,
    pub write_timeout: f64,
    pub idle_timeout: f64,
}

impl Default for SOCKSLimits {
    fn default() -> Self {
        Self {
            max_request_size: 1024,
            max_domain_length: 255,
            max_method_count: 255,

            max_connection_count: 1024,
            max_authentication_attempts: 3,
            max_datagram_size: 64 * 1024,

            connect_timeout: 10.0,
            handshake_timeout: 10.0,
            read_timeout: 30.0,
            write_timeout: 30.0,
            idle_timeout: 300.0,
        }
    }
}

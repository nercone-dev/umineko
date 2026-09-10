use alloc::vec::Vec;
use core::fmt;
use crate::errors::ARPError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ARPOperation {
    Request,
    Reply,
    Unknown(u16),
}

impl ARPOperation {
    pub fn number(&self) -> u16 {
        match self {
            Self::Request => 1,
            Self::Reply => 2,
            Self::Unknown(number) => *number,
        }
    }

    pub fn from_number(number: u16) -> Self {
        match number {
            1 => Self::Request,
            2 => Self::Reply,
            _ => Self::Unknown(number),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ARPHardwareType {
    Ethernet,
    IEEE802,
    Unknown(u16),
}

impl ARPHardwareType {
    pub fn number(&self) -> u16 {
        match self {
            Self::Ethernet => 1,
            Self::IEEE802 => 6,
            Self::Unknown(number) => *number,
        }
    }

    pub fn from_number(number: u16) -> Self {
        match number {
            1 => Self::Ethernet,
            6 => Self::IEEE802,
            _ => Self::Unknown(number),
        }
    }

    pub fn address_size(&self) -> Option<usize> {
        match self {
            Self::Ethernet | Self::IEEE802 => Some(6),
            Self::Unknown(_) => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HardwareAddress {
    kind: ARPHardwareType,
    address: Vec<u8>,
}

impl HardwareAddress {
    pub fn new(kind: ARPHardwareType, address: &[u8]) -> Result<Self, ARPError> {
        todo!()
    }

    pub fn parse(kind: ARPHardwareType, text: &str) -> Result<Self, ARPError> {
        todo!()
    }

    pub fn kind(&self) -> ARPHardwareType {
        self.kind
    }

    pub fn as_slice(&self) -> &[u8] {
        todo!()
    }

    pub fn broadcast(&self) -> bool {
        todo!()
    }

    pub fn multicast(&self) -> bool {
        todo!()
    }
}

impl fmt::Display for HardwareAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ARPLimits {
    pub max_packet_size: u16,
    pub max_cache_count: u32,
    pub max_request_count: u8,

    pub cache_lifetime: f64,
    pub revalidate_interval: f64,
    pub request_timeout: f64,
    pub read_timeout: f64,
    pub write_timeout: f64,
}

impl Default for ARPLimits {
    fn default() -> Self {
        Self {
            max_packet_size: 1500,
            max_cache_count: 4096,
            max_request_count: 3,

            cache_lifetime: 1200.0,
            revalidate_interval: 60.0,
            request_timeout: 1.0,
            read_timeout: 30.0,
            write_timeout: 30.0,
        }
    }
}

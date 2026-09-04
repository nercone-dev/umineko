use alloc::vec::Vec;
use core::fmt;
use crate::errors::NDPError;

use umineko_protocol_ip::IPAddress;
use umineko_protocol_icmp::ICMPType;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NDPType {
    RouterSolicitation,
    RouterAdvertisement,
    NeighborSolicitation,
    NeighborAdvertisement,
    Redirect,
}

impl NDPType {
    pub fn number(&self) -> u8 {
        match self {
            Self::RouterSolicitation => 133,
            Self::RouterAdvertisement => 134,
            Self::NeighborSolicitation => 135,
            Self::NeighborAdvertisement => 136,
            Self::Redirect => 137,
        }
    }

    pub fn from_number(number: u8) -> Option<Self> {
        match number {
            133 => Some(Self::RouterSolicitation),
            134 => Some(Self::RouterAdvertisement),
            135 => Some(Self::NeighborSolicitation),
            136 => Some(Self::NeighborAdvertisement),
            137 => Some(Self::Redirect),
            _ => None,
        }
    }

    pub fn icmp_type(&self) -> ICMPType {
        todo!()
    }

    pub const REQUIRED_HOP_LIMIT: u8 = 255;
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LinkLayerAddress(Vec<u8>);

impl LinkLayerAddress {
    pub fn new(address: &[u8]) -> Self {
        todo!()
    }

    pub fn as_slice(&self) -> &[u8] {
        todo!()
    }

    pub fn solicited_node(address: IPAddress) -> Result<IPAddress, NDPError> {
        todo!()
    }
}

impl fmt::Display for LinkLayerAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NDPOption {
    SourceLinkLayerAddress(LinkLayerAddress),
    TargetLinkLayerAddress(LinkLayerAddress),
    PrefixInformation { prefix: IPAddress, length: u8, on_link: bool, autonomous: bool, valid_lifetime: u32, preferred_lifetime: u32 },
    RedirectedHeader(Vec<u8>),
    MTU(u32),
    Unknown { kind: u8, data: Vec<u8> },
}

impl NDPOption {
    pub fn kind(&self) -> u8 {
        todo!()
    }

    pub fn encode(&self) -> Result<Vec<u8>, NDPError> {
        todo!()
    }

    pub fn decode(data: &[u8]) -> Result<(Self, usize), NDPError> {
        todo!()
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct NDPLimits {
    pub max_message_size: u16,
    pub max_option_count: u8,
    pub max_prefix_count: u8,
    pub max_cache_count: u32,

    pub max_solicitation_count: u8,
    pub max_duplicate_probe_count: u8,

    pub reachable_lifetime: f64,
    pub stale_lifetime: f64,
    pub solicitation_interval: f64,
    pub solicitation_timeout: f64,
}

impl Default for NDPLimits {
    fn default() -> Self {
        Self {
            max_message_size: 1280,
            max_option_count: 16,
            max_prefix_count: 8,
            max_cache_count: 4096,

            max_solicitation_count: 3,
            max_duplicate_probe_count: 1,

            reachable_lifetime: 30.0,
            stale_lifetime: 1200.0,
            solicitation_interval: 1.0,
            solicitation_timeout: 3.0,
        }
    }
}

use core::{fmt, str::FromStr};
use crate::errors::IPError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IPVersion {
    V4,
    V6,
}

impl IPVersion {
    pub fn number(&self) -> u8 {
        match self {
            Self::V4 => 4,
            Self::V6 => 6,
        }
    }

    pub fn from_number(number: u8) -> Option<Self> {
        match number {
            4 => Some(Self::V4),
            6 => Some(Self::V6),
            _ => None,
        }
    }

    pub fn address_size(&self) -> usize {
        match self {
            Self::V4 => 4,
            Self::V6 => 16,
        }
    }

    pub fn minimum_mtu(&self) -> usize {
        match self {
            Self::V4 => 576,
            Self::V6 => 1280,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::V4 => "IPv4",
            Self::V6 => "IPv6",
        }
    }
}

impl fmt::Display for IPVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IPAddress {
    V4([u8; 4]),
    V6([u8; 16]),
}

impl IPAddress {
    pub const UNSPECIFIED_V4: Self = Self::V4([0; 4]);
    pub const UNSPECIFIED_V6: Self = Self::V6([0; 16]);
    pub const LOOPBACK_V4: Self = Self::V4([127, 0, 0, 1]);
    pub const LOOPBACK_V6: Self = Self::V6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

    pub fn version(&self) -> IPVersion {
        match self {
            Self::V4(_) => IPVersion::V4,
            Self::V6(_) => IPVersion::V6,
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        match self {
            Self::V4(address) => address,
            Self::V6(address) => address,
        }
    }

    pub fn parse(text: &str) -> Result<Self, IPError> {
        todo!()
    }

    pub fn unspecified(&self) -> bool {
        todo!()
    }

    pub fn loopback(&self) -> bool {
        todo!()
    }

    pub fn multicast(&self) -> bool {
        todo!()
    }

    pub fn private(&self) -> bool {
        todo!()
    }

    pub fn contained(&self, network: &Self, prefix: u8) -> bool {
        todo!()
    }

    pub fn map(&self, version: IPVersion) -> Option<Self> {
        todo!()
    }
}

impl fmt::Display for IPAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl FromStr for IPAddress {
    type Err = IPError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IPProtocol {
    ICMPV4,
    IGMP,
    TCP,
    UDP,
    IPV6,
    ICMPV6,
    SCTP,
    Unknown(u8),
}

impl IPProtocol {
    pub fn number(&self) -> u8 {
        match self {
            Self::ICMPV4 => 1,
            Self::IGMP => 2,
            Self::TCP => 6,
            Self::UDP => 17,
            Self::IPV6 => 41,
            Self::ICMPV6 => 58,
            Self::SCTP => 132,
            Self::Unknown(number) => *number,
        }
    }

    pub fn from_number(number: u8) -> Self {
        match number {
            1 => Self::ICMPV4,
            2 => Self::IGMP,
            6 => Self::TCP,
            17 => Self::UDP,
            41 => Self::IPV6,
            58 => Self::ICMPV6,
            132 => Self::SCTP,
            _ => Self::Unknown(number),
        }
    }

    pub fn pseudo_header(&self) -> bool {
        matches!(self, Self::TCP | Self::UDP | Self::ICMPV6 | Self::SCTP)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IPToS {
    pub differentiated_services: u8,
    pub congestion_notification: u8,
}

impl Default for IPToS {
    fn default() -> Self {
        Self { differentiated_services: 0, congestion_notification: 0 }
    }
}

impl IPToS {
    pub fn encode(&self) -> u8 {
        todo!()
    }

    pub fn decode(byte: u8) -> Self {
        todo!()
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct IPLimits {
    pub max_packet_size: u32,
    pub max_payload_size: u32,
    pub max_header_size: u16,
    pub max_option_count: u8,
    pub max_extension_header_count: u8,

    pub max_fragment_count: u16,
    pub max_reassembly_size: u32,
    pub max_reassembly_count: u32,

    pub max_connection_count: u64,

    pub reassembly_timeout: f64,
    pub read_timeout: f64,
    pub write_timeout: f64,
}

impl Default for IPLimits {
    fn default() -> Self {
        Self {
            max_packet_size: 64 * 1024,
            max_payload_size: 64 * 1024,
            max_header_size: 60,
            max_option_count: 16,
            max_extension_header_count: 8,

            max_fragment_count: 1024,
            max_reassembly_size: 64 * 1024,
            max_reassembly_count: 1024,

            max_connection_count: 1024,

            reassembly_timeout: 60.0,
            read_timeout: 30.0,
            write_timeout: 30.0,
        }
    }
}

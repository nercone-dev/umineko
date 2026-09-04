use alloc::{string::String, vec::Vec};
use core::fmt;
use crate::errors::DHCPError;

use umineko_protocol_ip::{IPVersion, IPAddress};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DHCPVersion {
    V4,
    V6,
}

impl DHCPVersion {
    pub fn ip_version(&self) -> IPVersion {
        match self {
            Self::V4 => IPVersion::V4,
            Self::V6 => IPVersion::V6,
        }
    }

    pub fn client_port(&self) -> u16 {
        match self {
            Self::V4 => 68,
            Self::V6 => 546,
        }
    }

    pub fn server_port(&self) -> u16 {
        match self {
            Self::V4 => 67,
            Self::V6 => 547,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::V4 => "DHCPv4",
            Self::V6 => "DHCPv6",
        }
    }
}

impl fmt::Display for DHCPVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DHCPMessageType {
    Discover,
    Offer,
    Request,
    Decline,
    Acknowledge,
    NegativeAcknowledge,
    Release,
    Inform,
    Solicit,
    Advertise,
    Reconfigure,
    Unknown(u8),
}

impl DHCPMessageType {
    pub fn number(&self, version: DHCPVersion) -> Option<u8> {
        todo!()
    }

    pub fn from_number(version: DHCPVersion, number: u8) -> Self {
        todo!()
    }

    pub fn allowed(&self, version: DHCPVersion) -> bool {
        todo!()
    }

    pub fn from_client(&self) -> bool {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DHCPClientID(Vec<u8>);

impl DHCPClientID {
    pub const MAXIMUM_LENGTH: usize = 255;

    pub fn new(data: &[u8]) -> Result<Self, DHCPError> {
        todo!()
    }

    pub fn from_hardware(kind: u8, address: &[u8]) -> Result<Self, DHCPError> {
        todo!()
    }

    pub fn as_slice(&self) -> &[u8] {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DHCPOption {
    MessageType(DHCPMessageType),
    ServerID(Vec<u8>),
    ClientID(DHCPClientID),
    RequestedAddress(IPAddress),
    SubnetMask(IPAddress),
    Router(Vec<IPAddress>),
    NameServer(Vec<IPAddress>),
    DomainName(String),
    LeaseTime(u32),
    RenewalTime(u32),
    RebindingTime(u32),
    MaximumMessageSize(u16),
    ParameterRequestList(Vec<u8>),
    Message(String),
    RelayAgent(Vec<u8>),
    Unknown { kind: u16, data: Vec<u8> },
}

impl DHCPOption {
    pub fn kind(&self, version: DHCPVersion) -> Option<u16> {
        todo!()
    }

    pub fn encode(&self, version: DHCPVersion) -> Result<Vec<u8>, DHCPError> {
        todo!()
    }

    pub fn decode(data: &[u8], version: DHCPVersion) -> Result<(Self, usize), DHCPError> {
        todo!()
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DHCPLimits {
    pub max_message_size: u16,
    pub max_option_count: u8,
    pub max_option_size: u16,

    pub max_lease_count: u32,
    pub max_retry_count: u8,
    pub max_duplicate_probe_count: u8,

    pub default_lease_time: u32,
    pub max_lease_time: u32,
    pub min_lease_time: u32,

    pub discover_timeout: f64,
    pub request_timeout: f64,
    pub read_timeout: f64,
    pub write_timeout: f64,
}

impl Default for DHCPLimits {
    fn default() -> Self {
        Self {
            max_message_size: 1500,
            max_option_count: 64,
            max_option_size: 1024,

            max_lease_count: 64 * 1024,
            max_retry_count: 4,
            max_duplicate_probe_count: 2,

            default_lease_time: 43200,
            max_lease_time: 604800,
            min_lease_time: 300,

            discover_timeout: 10.0,
            request_timeout: 10.0,
            read_timeout: 30.0,
            write_timeout: 30.0,
        }
    }
}

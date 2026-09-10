use core::fmt;

use umineko_protocol_ip::IPVersion;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ICMPVersion {
    V4,
    V6,
}

impl ICMPVersion {
    pub fn ip_version(&self) -> IPVersion {
        match self {
            Self::V4 => IPVersion::V4,
            Self::V6 => IPVersion::V6,
        }
    }

    pub fn from_ip_version(version: IPVersion) -> Self {
        match version {
            IPVersion::V4 => Self::V4,
            IPVersion::V6 => Self::V6,
        }
    }

    pub fn pseudo_header(&self) -> bool {
        matches!(self, Self::V6)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::V4 => "ICMPv4",
            Self::V6 => "ICMPv6",
        }
    }
}

impl fmt::Display for ICMPVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ICMPType {
    EchoRequest,
    EchoReply,
    DestinationUnreachable,
    TimeExceeded,
    ParameterProblem,
    PacketTooBig,
    SourceQuench,
    Redirect,
    RouterSolicitation,
    RouterAdvertisement,
    NeighborSolicitation,
    NeighborAdvertisement,
    Unknown(u8),
}

impl ICMPType {
    pub fn number(&self, version: ICMPVersion) -> Option<u8> {
        todo!()
    }

    pub fn from_number(version: ICMPVersion, number: u8) -> Self {
        todo!()
    }

    pub fn error(&self) -> bool {
        matches!(self, Self::DestinationUnreachable | Self::TimeExceeded | Self::ParameterProblem | Self::PacketTooBig)
    }

    pub fn query(&self) -> bool {
        matches!(self, Self::EchoRequest | Self::RouterSolicitation | Self::NeighborSolicitation)
    }

    pub fn as_str(&self) -> &'static str {
        todo!()
    }
}

impl fmt::Display for ICMPType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ICMPCode(pub u8);

impl ICMPCode {
    pub const DEFAULT: Self = Self(0);

    pub fn describe(&self, kind: ICMPType, version: ICMPVersion) -> &'static str {
        todo!()
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ICMPLimits {
    pub max_packet_size: u32,
    pub max_payload_size: u32,
    pub max_quotation_size: u32,

    pub max_connection_count: u64,
    pub max_error_rate: u32,

    pub read_timeout: f64,
    pub write_timeout: f64,
    pub echo_timeout: f64,
}

impl Default for ICMPLimits {
    fn default() -> Self {
        Self {
            max_packet_size: 64 * 1024,
            max_payload_size: 64 * 1024,
            max_quotation_size: 1280,

            max_connection_count: 1024,
            max_error_rate: 100,

            read_timeout: 30.0,
            write_timeout: 30.0,
            echo_timeout: 5.0,
        }
    }
}

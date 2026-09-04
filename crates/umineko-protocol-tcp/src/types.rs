use alloc::vec::Vec;
use core::fmt;

use umineko_protocol_ip::IPAddress;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TCPPort(pub u16);

impl TCPPort {
    pub const ANY: Self = Self(0);

    pub fn reserved(&self) -> bool {
        self.0 < 1024
    }

    pub fn ephemeral(&self) -> bool {
        self.0 >= 49152
    }
}

impl fmt::Display for TCPPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TCPEndpoint {
    pub address: IPAddress,
    pub port: TCPPort,
}

impl fmt::Display for TCPEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TCPFlags {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
    pub urg: bool,
    pub ece: bool,
    pub cwr: bool,
}

impl Default for TCPFlags {
    fn default() -> Self {
        Self { fin: false, syn: false, rst: false, psh: false, ack: false, urg: false, ece: false, cwr: false }
    }
}

impl TCPFlags {
    pub fn encode(&self) -> u8 {
        todo!()
    }

    pub fn decode(byte: u8) -> Self {
        todo!()
    }

    pub fn consumes_sequence(&self) -> bool {
        self.syn || self.fin
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TCPState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}

impl TCPState {
    pub fn established(&self) -> bool {
        matches!(self, Self::Established)
    }

    pub fn sendable(&self) -> bool {
        matches!(self, Self::Established | Self::CloseWait)
    }

    pub fn receivable(&self) -> bool {
        matches!(self, Self::Established | Self::FinWait1 | Self::FinWait2)
    }

    pub fn closing(&self) -> bool {
        matches!(self, Self::FinWait1 | Self::FinWait2 | Self::CloseWait | Self::Closing | Self::LastAck | Self::TimeWait)
    }

    pub fn as_str(&self) -> &'static str {
        todo!()
    }
}

impl fmt::Display for TCPState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TCPOption {
    MaximumSegmentSize(u16),
    WindowScale(u8),
    SackPermitted,
    Sack(Vec<(u32, u32)>),
    Timestamp { value: u32, echo: u32 },
    NoOperation,
    EndOfList,
    Unknown { kind: u8, data: Vec<u8> },
}

impl TCPOption {
    pub fn kind(&self) -> u8 {
        todo!()
    }

    pub fn len(&self) -> usize {
        todo!()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TCPLimits {
    pub max_segment_size: u16,
    pub max_option_count: u8,
    pub max_window_size: u32,

    pub max_connection_count: u64,
    pub max_backlog: u32,
    pub max_send_buffer_size: u32,
    pub max_receive_buffer_size: u32,
    pub max_reorder_count: u16,

    pub max_retransmit_count: u8,
    pub max_keepalive_count: u8,

    pub connect_timeout: f64,
    pub read_timeout: f64,
    pub write_timeout: f64,
    pub close_timeout: f64,
    pub keepalive_interval: f64,
    pub linger_timeout: f64,
}

impl Default for TCPLimits {
    fn default() -> Self {
        Self {
            max_segment_size: 1460,
            max_option_count: 16,
            max_window_size: 1024 * 1024,

            max_connection_count: 1024,
            max_backlog: 128,
            max_send_buffer_size: 256 * 1024,
            max_receive_buffer_size: 256 * 1024,
            max_reorder_count: 1024,

            max_retransmit_count: 6,
            max_keepalive_count: 9,

            connect_timeout: 10.0,
            read_timeout: 30.0,
            write_timeout: 30.0,
            close_timeout: 10.0,
            keepalive_interval: 75.0,
            linger_timeout: 60.0,
        }
    }
}

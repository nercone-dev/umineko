use core::fmt;

use umineko_protocol_ip::IPAddress;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UDPPort(pub u16);

impl UDPPort {
    pub const ANY: Self = Self(0);

    pub fn reserved(&self) -> bool {
        self.0 < 1024
    }

    pub fn ephemeral(&self) -> bool {
        self.0 >= 49152
    }
}

impl fmt::Display for UDPPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UDPEndpoint {
    pub address: IPAddress,
    pub port: UDPPort,
}

impl fmt::Display for UDPEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct UDPLimits {
    pub max_datagram_size: u32,
    pub max_payload_size: u32,

    pub max_connection_count: u64,
    pub max_send_buffer_size: u32,
    pub max_receive_buffer_size: u32,
    pub max_batch_count: u16,

    pub read_timeout: f64,
    pub write_timeout: f64,
    pub path_discovery_interval: f64,
}

impl Default for UDPLimits {
    fn default() -> Self {
        Self {
            max_datagram_size: 64 * 1024,
            max_payload_size: 64 * 1024 - 8,

            max_connection_count: 1024,
            max_send_buffer_size: 256 * 1024,
            max_receive_buffer_size: 256 * 1024,
            max_batch_count: 64,

            read_timeout: 30.0,
            write_timeout: 30.0,
            path_discovery_interval: 600.0,
        }
    }
}

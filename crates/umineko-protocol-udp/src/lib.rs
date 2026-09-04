//! UDP.

#![no_std]
#![allow(async_fn_in_trait)]

extern crate alloc;

pub mod api {
    pub mod client;
    pub mod server;

    pub use client::{UDPClient, UDPClientConfig};
    pub use server::{UDPServer, UDPServerConfig, UDPHandler};
}

pub mod helpers {
    pub mod checksum;
    pub mod fragmentation;

    pub use checksum::{UDPChecksum};
    pub use fragmentation::{UDPPathDiscovery};
}

pub mod protocol {
    pub mod packet;
    pub mod connection;

    pub use packet::{UDPPacket, UDPHeader};
    pub use connection::{UDPConnection, UDPSocket};
}

pub mod errors;
pub mod types;
pub mod provider;

pub use errors::{UDPError};
pub use types::{UDPPort, UDPEndpoint, UDPLimits};
pub use provider::{UDPProvider, UDPProviderRequest, UDPProviders};

//! TCP.

#![no_std]
#![allow(async_fn_in_trait)]

extern crate alloc;

pub mod api {
    pub mod client;
    pub mod server;

    pub use client::{TCPClient, TCPClientConfig};
    pub use server::{TCPServer, TCPServerConfig, TCPHandler};
}

pub mod helpers {
    pub mod checksum;
    pub mod congestion;

    pub use checksum::{TCPChecksum};
    pub use congestion::{TCPCongestion, TCPCongestionState};
}

pub mod protocol {
    pub mod packet;
    pub mod connection;

    pub use packet::{TCPPacket, TCPHeader};
    pub use connection::{TCPConnection, TCPListener};
}

pub mod errors;
pub mod types;
pub mod provider;

pub use errors::{TCPError};
pub use types::{TCPPort, TCPEndpoint, TCPFlags, TCPState, TCPOption, TCPLimits};
pub use provider::{TCPProvider, TCPProviderRequest, TCPProviders};

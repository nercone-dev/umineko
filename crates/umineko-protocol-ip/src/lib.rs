//! IP.

#![no_std]
#![allow(async_fn_in_trait)]

extern crate alloc;

pub mod api {
    pub mod client;
    pub mod server;

    pub use client::{IPClient, IPClientConfig};
    pub use server::{IPServer, IPServerConfig, IPHandler};
}

pub mod helpers {
    pub mod checksum;
    pub mod fragmentation;
    pub mod routing;

    pub use checksum::{IPChecksum};
    pub use fragmentation::{IPFragmenter, IPReassembler};
    pub use routing::{IPRoute, IPRoutingTable};
}

pub mod protocol {
    pub mod base;
    #[cfg(feature = "ipv4")]
    pub mod v4;
    #[cfg(feature = "ipv6")]
    pub mod v6;

    pub use base::{IPPacket, IPConnection};
    #[cfg(feature = "ipv4")]
    pub use v4::{IPv4Packet, IPv4Header, IPv4Option, IPv4Connection};
    #[cfg(feature = "ipv6")]
    pub use v6::{IPv6Packet, IPv6Header, IPv6ExtensionHeader, IPv6Connection};
}

pub mod errors;
pub mod types;
pub mod provider;

pub use errors::{IPError};
pub use types::{IPVersion, IPAddress, IPProtocol, IPToS, IPLimits};
pub use provider::{IPProvider, IPProviderRequest, IPProviders};

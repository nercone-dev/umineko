//! ICMP.

#![no_std]
#![allow(async_fn_in_trait)]

extern crate alloc;

pub mod api {
    pub mod client;
    pub mod server;

    pub use client::{ICMPClient, ICMPClientConfig};
    pub use server::{ICMPServer, ICMPServerConfig, ICMPHandler};
}

pub mod helpers {
    pub mod checksum;
    pub mod echo;

    pub use checksum::{ICMPChecksum};
    pub use echo::{ICMPEchoRequest, ICMPEchoReply};
}

pub mod protocol {
    pub mod base;
    pub mod v4;
    pub mod v6;

    pub use base::{ICMPPacket, ICMPConnection};
    pub use v4::{ICMPv4Packet, ICMPv4Connection};
    pub use v6::{ICMPv6Packet, ICMPv6Connection};
}

pub mod errors;
pub mod types;
pub mod provider;

pub use errors::{ICMPError};
pub use types::{ICMPVersion, ICMPType, ICMPCode, ICMPLimits};
pub use provider::{ICMPProvider, ICMPProviderRequest, ICMPProviders};

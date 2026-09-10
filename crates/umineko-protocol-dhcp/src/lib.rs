//! DHCP.

#![no_std]
#![allow(async_fn_in_trait)]

extern crate alloc;

pub mod api {
    pub mod client;
    pub mod server;

    pub use client::{DHCPClient, DHCPClientConfig};
    pub use server::{DHCPServer, DHCPServerConfig, DHCPHandler};
}

pub mod helpers {
    pub mod lease;

    pub use lease::{DHCPLease, DHCPLeaseState, DHCPPool};
}

pub mod protocol {
    pub mod base;
    #[cfg(feature = "dhcpv4")]
    pub mod v4;
    #[cfg(feature = "dhcpv6")]
    pub mod v6;

    pub use base::{DHCPMessage, DHCPConnection};
    #[cfg(feature = "dhcpv4")]
    pub use v4::{DHCPv4Message, DHCPv4Connection};
    #[cfg(feature = "dhcpv6")]
    pub use v6::{DHCPv6Message, DHCPv6Connection};
}

pub mod errors;
pub mod types;

pub use errors::{DHCPError};
pub use types::{DHCPVersion, DHCPMessageType, DHCPOption, DHCPClientID, DHCPLimits};

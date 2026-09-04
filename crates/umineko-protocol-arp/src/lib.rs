//! ARP.

#![no_std]
#![allow(async_fn_in_trait)]

extern crate alloc;

pub mod api {
    pub mod client;
    pub mod server;

    pub use client::{ARPClient, ARPClientConfig};
    pub use server::{ARPServer, ARPServerConfig, ARPHandler};
}

pub mod helpers {
    pub mod cache;

    pub use cache::{ARPCache, ARPEntry, ARPEntryState};
}

pub mod protocol {
    pub mod connection;
    pub mod packet;

    pub use connection::{ARPConnection};
    pub use packet::{ARPPacket};
}

pub mod errors;
pub mod types;

pub use errors::{ARPError};
pub use types::{ARPOperation, ARPHardwareType, HardwareAddress, ARPLimits};

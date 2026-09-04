//! NDP.

#![no_std]
#![allow(async_fn_in_trait)]

extern crate alloc;

pub mod api {
    pub mod client;
    pub mod server;

    pub use client::{NDPClient, NDPClientConfig};
    pub use server::{NDPServer, NDPServerConfig, NDPHandler};
}

pub mod helpers {
    pub mod cache;

    pub use cache::{NDPCache, NDPEntry, NDPEntryState};
}

pub mod protocol {
    pub mod base;
    pub mod connection;
    pub mod neighbor;
    pub mod router;
    pub mod redirect;

    pub use base::{NDPMessage};
    pub use connection::{NDPConnection};
    pub use neighbor::{NeighborSolicitation, NeighborAdvertisement};
    pub use router::{RouterSolicitation, RouterAdvertisement, RouterPrefix};
    pub use redirect::{Redirect};
}

pub mod errors;
pub mod types;

pub use errors::{NDPError};
pub use types::{NDPType, NDPOption, LinkLayerAddress, NDPLimits};

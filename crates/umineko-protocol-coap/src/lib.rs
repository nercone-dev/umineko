//! CoAP.

#![no_std]
#![allow(async_fn_in_trait)]

extern crate alloc;

pub mod api {
    pub mod client;
    pub mod server;

    pub use client::{CoAPClient, CoAPClientConfig};
    pub use server::{CoAPServer, CoAPServerConfig, CoAPHandler};
}

pub mod helpers {
    pub mod block;
    pub mod observe;

    pub use block::{CoAPBlock, CoAPBlockTransfer};
    pub use observe::{CoAPObserver, CoAPObservation};
}

pub mod protocol {
    pub mod base;
    pub mod message;

    pub use base::{CoAPConnection};
    pub use message::{CoAPMessage, CoAPToken};
}

pub mod errors;
pub mod types;

pub use errors::{CoAPError};
pub use types::{CoAPVersion, CoAPType, CoAPCode, CoAPOption, CoAPContentFormat, CoAPLimits};

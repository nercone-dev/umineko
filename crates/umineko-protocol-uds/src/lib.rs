//! Unix domain sockets.

#![no_std]
#![allow(async_fn_in_trait)]

extern crate alloc;

pub mod api {
    pub mod client;
    pub mod server;

    pub use client::{UDSClient, UDSClientConfig};
    pub use server::{UDSServer, UDSServerConfig, UDSHandler};
}

pub mod helpers {
    pub mod ancillary;
    pub mod credentials;

    pub use ancillary::{UDSAncillary};
    pub use credentials::{UDSCredentials};
}

pub mod protocol {
    pub mod base;
    pub mod stream;
    pub mod datagram;
    pub mod seqpacket;

    pub use base::{UDSConnection, UDSListener};
    pub use stream::{UDSStreamConnection, UDSStreamListener};
    pub use datagram::{UDSDatagramConnection};
    pub use seqpacket::{UDSSeqpacketConnection, UDSSeqpacketListener};
}

pub mod errors;
pub mod types;
pub mod provider;

pub use errors::{UDSError};
pub use types::{UDSPath, UDSType, UDSLimits};
pub use provider::{UDSProvider, UDSProviderRequest, UDSProviders};

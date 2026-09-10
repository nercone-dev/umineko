//! SOCKS.

#![no_std]
#![allow(async_fn_in_trait)]

extern crate alloc;

pub mod api {
    pub mod client;
    pub mod server;

    pub use client::{SOCKSClient, SOCKSClientConfig};
    pub use server::{SOCKSServer, SOCKSServerConfig, SOCKSHandler};
}

pub mod helpers {
    pub mod authentication;

    pub use authentication::{SOCKSAuthentication, SOCKSCredentials};
}

pub mod protocol {
    pub mod base;
    #[cfg(feature = "socks4")]
    pub mod v4;
    #[cfg(feature = "socks5")]
    pub mod v5;

    pub use base::{SOCKSConnection};
    #[cfg(feature = "socks4")]
    pub use v4::{SOCKS4Connection};
    #[cfg(feature = "socks5")]
    pub use v5::{SOCKS5Connection};
}

pub mod errors;
pub mod types;

pub use errors::{SOCKSError};
pub use types::{SOCKSVersion, SOCKSCommand, SOCKSAddress, SOCKSReply, SOCKSLimits};

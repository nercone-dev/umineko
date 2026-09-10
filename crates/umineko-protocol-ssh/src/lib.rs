//! SSH.

#![no_std]
#![allow(async_fn_in_trait)]
#![allow(non_camel_case_types)]

extern crate alloc;

pub mod api {
    pub mod client;
    pub mod server;

    pub use client::{SSHClient, SSHClientConfig};
    pub use server::{SSHServer, SSHServerConfig, SSHHandler};
}

pub mod helpers {
    pub mod kex;
    pub mod cipher;
    pub mod mac;
    pub mod key;

    pub use kex::{SSHKeyExchange, SSHKeyExchangeState};
    pub use cipher::{SSHCipher};
    pub use mac::{SSHMac, SSHCompression};
    pub use key::{SSHKey, SSHKeyType, SSHFingerprint, SSHKnownHosts};
}

pub mod protocol {
    pub mod base;
    pub mod transport;
    pub mod authentication;
    pub mod connection;

    pub use base::{SSHConnection, SSHPacket};
    pub use transport::{SSHTransport};
    pub use authentication::{SSHAuthentication, SSHAuthenticationMethod};
    pub use connection::{SSHChannel, SSHChannelType, SSHChannelRequest};
}

pub mod errors;
pub mod types;

pub use errors::{SSHError, SSHDisconnectReason};
pub use types::{SSHVersion, SSHMessageType, SSHRole, SSHLimits};

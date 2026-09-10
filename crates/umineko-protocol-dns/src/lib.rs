//! DNS.

#![no_std]
#![allow(async_fn_in_trait)]

extern crate alloc;

pub mod api {
    pub mod client;
    pub mod server;

    pub use client::{DNSClient, DNSClientConfig};
    pub use server::{DNSServer, DNSServerConfig, DNSHandler};
}

pub mod helpers {
    pub mod cache;
    pub mod resolver;
    #[cfg(feature = "dnssec")]
    pub mod dnssec;

    pub use cache::{DNSCache, DNSCacheEntry};
    pub use resolver::{DNSResolver, DNSResolverMode};
    #[cfg(feature = "dnssec")]
    pub use dnssec::{DNSSEC, DNSSECAlgorithm, DNSSECStatus};
}

pub mod protocol {
    pub mod base;
    #[cfg(feature = "udp")]
    pub mod udp;
    #[cfg(feature = "tcp")]
    pub mod tcp;
    #[cfg(feature = "quic")]
    pub mod quic;
    #[cfg(feature = "tls")]
    pub mod tls;
    #[cfg(feature = "https")]
    pub mod https;

    pub use base::{DNSConnection, DNSTransport};
    #[cfg(feature = "udp")]
    pub use udp::{DNSUDPConnection};
    #[cfg(feature = "tcp")]
    pub use tcp::{DNSTCPConnection};
    #[cfg(feature = "quic")]
    pub use quic::{DNSQUICConnection};
    #[cfg(feature = "tls")]
    pub use tls::{DNSTLSConnection};
    #[cfg(feature = "https")]
    pub use https::{DNSHTTPSConnection};
}

pub mod errors;
pub mod types;
pub mod provider;

pub use errors::{DNSError};
pub use provider::{DNSProvider, DNSProviderRequest, DNSProviders};
pub use types::{DNSName, DNSType, DNSClass, DNSOpcode, DNSResponseCode, DNSQuestion, DNSRecord, DNSMessage, DNSLimits};

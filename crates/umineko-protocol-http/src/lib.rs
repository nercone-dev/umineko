//! HTTP.

#![no_std]
#![allow(async_fn_in_trait)]

extern crate alloc;

pub mod api {
    pub mod client;
    pub mod server;

    pub use client::{HTTPClient, HTTPClientConfig};
    pub use server::{HTTPServer, HTTPServerConfig, HTTPHandler};
}

pub mod helpers {
    pub mod compression;
    pub mod cookie;
    pub mod dns;
    pub mod hsts;
    pub mod hpack;
    pub mod qpack;

    pub use compression::{HTTPCompression};
    pub use cookie::{HTTPCookie, HTTPCookies, HTTPCookieSameSite};
    pub use dns::{HTTPSRecord, HTTPSRecordStore};
    pub use hsts::{HSTSPolicy, HSTSStore};
    pub use hpack::{HPACK, HPACKEncoder, HPACKDecoder};
    pub use qpack::{QPACK, QPACKEncoder, QPACKDecoder};
}

pub mod protocol {
    pub mod base;
    pub mod stream;
    #[cfg(any(feature = "http10", feature = "http11"))]
    pub mod h1;
    #[cfg(feature = "http20")]
    pub mod h2;
    #[cfg(feature = "http30")]
    pub mod h3;
    #[cfg(feature = "websocket")]
    pub mod ws;
    pub mod handler;

    pub use base::{HTTPConnection};
    pub use stream::{HTTPStream};
    #[cfg(any(feature = "http10", feature = "http11"))]
    pub use h1::{H1Connection};
    #[cfg(feature = "http20")]
    pub use h2::{H2Connection, H2Setting};
    #[cfg(feature = "http30")]
    pub use h3::{H3Connection, H3Setting};
    #[cfg(feature = "websocket")]
    pub use ws::{WSConnection, WSOpcode, WSCloseCode, WSFrame, WSMessage};
    #[cfg(feature = "uds")]
    pub use handler::{HTTPUDSHandler};
    pub use handler::{HTTPTCPHandler};
    #[cfg(feature = "http30")]
    pub use handler::{HTTPQUICHandler};
}

pub mod errors;
pub mod types;
pub mod provider;

pub use errors::{HTTPError};
pub use provider::{HTTPProvider, HTTPProviderRequest, HTTPProviders};
pub use types::{HTTPPort, HTTPVersion, HTTPMethod, HTTPRole, HTTPHeaderCase, HTTPHeader, HTTPHeaders, HTTPBody, HTTPStreamID, HTTPConnectionID, HTTPMessage, HTTPLimits};

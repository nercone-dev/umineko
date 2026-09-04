//! TLS.

#![no_std]
#![allow(async_fn_in_trait)]
#![allow(non_camel_case_types)]

extern crate alloc;

pub mod api {
    pub mod client;
    pub mod server;

    pub use client::{TLSClient, TLSClientConfig};
    pub use server::{TLSServer, TLSServerConfig, TLSHandler};
}

pub mod helpers {
    pub mod handshake;
    pub mod certificate;
    pub mod key_schedule;
    pub mod sni;
    pub mod alpn;
    pub mod session;

    pub use handshake::{TLSHandshake, TLSHandshakeType, TLSHandshakeState};
    pub use certificate::{TLSCertificate, TLSCertificateChain, TLSCertificateVerifier};
    pub use key_schedule::{TLSKeySchedule, TLSSecret};
    pub use sni::{TLSServerName};
    pub use alpn::{TLSApplicationProtocol};
    pub use session::{TLSSession, TLSSessionStore, TLSSessionTicket};
}

pub mod protocol {
    pub mod base;
    #[cfg(feature = "tls10")]
    pub mod tls10;
    #[cfg(feature = "tls11")]
    pub mod tls11;
    #[cfg(feature = "tls12")]
    pub mod tls12;
    #[cfg(feature = "tls13")]
    pub mod tls13;
    #[cfg(feature = "dtls")]
    pub mod dtls;

    pub use base::{TLSConnection, TLSRecord, TLSContentType};
    #[cfg(feature = "tls10")]
    pub use tls10::{TLS10Connection};
    #[cfg(feature = "tls11")]
    pub use tls11::{TLS11Connection};
    #[cfg(feature = "tls12")]
    pub use tls12::{TLS12Connection};
    #[cfg(feature = "tls13")]
    pub use tls13::{TLS13Connection};
    #[cfg(feature = "dtls")]
    pub use dtls::{DTLSVersion, DTLSConnection};
}

pub mod errors;
pub mod types;
pub mod provider;

pub use errors::{TLSError, TLSAlert};
pub use types::{TLSVersion, TLSRole, TLSGroup, TLSCipher, TLSSignatureScheme, TLSExtension, TLSLimits};
pub use provider::{TLSProvider, TLSProviderRequest, TLSProviders};

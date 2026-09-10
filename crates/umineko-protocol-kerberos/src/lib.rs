//! Kerberos.

#![no_std]
#![allow(async_fn_in_trait)]
#![allow(non_camel_case_types)]

extern crate alloc;

pub mod api {
    pub mod client;
    pub mod server;

    pub use client::{KerberosClient, KerberosClientConfig};
    pub use server::{KerberosServer, KerberosServerConfig, KerberosHandler};
}

pub mod helpers {
    pub mod key;
    pub mod keytab;
    pub mod credentials;
    pub mod nfold;

    pub use key::{KerberosKeyDerivation, KerberosKey};
    pub use keytab::{KerberosKeytab, KerberosKeytabEntry};
    pub use credentials::{KerberosCredentials, KerberosCredentialCache};
    pub use nfold::{KerberosNFold};
}

pub mod protocol {
    pub mod base;
    pub mod messages;

    pub use base::{KerberosConnection};
    pub use messages::{KerberosMessage, KerberosEncryptedData, KerberosTicket, KerberosTicketPart, KerberosAuthenticator, KerberosAPRequest, KerberosAPReply, KerberosKDCRequest, KerberosKDCReply, KerberosSafe, KerberosPrivate, KerberosCredential, KerberosErrorMessage};
}

pub mod errors;
pub mod types;

pub use errors::{KerberosError, KerberosErrorCode};
pub use types::{KerberosVersion, KerberosTransport, KerberosMessageType, KerberosNameType, KerberosPrincipalName, KerberosPrincipal, KerberosKeyUsage, KerberosEncryptionTypeSpecification, KerberosEncryptionType, KerberosChecksumTypeSpecification, KerberosChecksumType, KerberosLimits};

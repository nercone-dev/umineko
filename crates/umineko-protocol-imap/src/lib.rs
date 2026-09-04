//! IMAP.

#![no_std]
#![allow(async_fn_in_trait)]

extern crate alloc;

pub mod api {
    pub mod client;
    pub mod server;

    pub use client::{IMAPClient, IMAPClientConfig};
    pub use server::{IMAPServer, IMAPServerConfig, IMAPHandler};
}

pub mod helpers {
    pub mod mailbox;
    pub mod search;
    pub mod sequence;
    pub mod literal;

    pub use mailbox::{IMAPMailbox, IMAPMailboxAttribute};
    pub use search::{IMAPSearchKey, IMAPSortKey};
    pub use sequence::{IMAPSequenceSet, IMAPSequence};
    pub use literal::{IMAPLiteral, IMAPString};
}

pub mod protocol {
    pub mod base;
    pub mod session;
    pub mod idle;
    pub mod condstore;

    pub use base::{IMAPConnection};
    pub use session::{IMAPSession};
    pub use idle::{IMAPIdle};
    pub use condstore::{IMAPCondStore, IMAPModSequence};
}

pub mod errors;
pub mod types;

pub use errors::{IMAPError};
pub use types::{IMAPTag, IMAPCommand, IMAPResponse, IMAPStatus, IMAPFlag, IMAPState, IMAPCapability, IMAPLimits};

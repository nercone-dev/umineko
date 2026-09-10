//! FTP.

#![no_std]
#![allow(async_fn_in_trait)]

extern crate alloc;

pub mod api {
    pub mod client;
    pub mod server;

    pub use client::{FTPClient, FTPClientConfig};
    pub use server::{FTPServer, FTPServerConfig, FTPHandler};
}

pub mod helpers {
    pub mod listing;

    pub use listing::{FTPEntry, FTPEntryKind, FTPListing};
}

pub mod protocol {
    pub mod base;
    pub mod session;
    pub mod data;

    pub use base::{FTPConnection};
    pub use session::{FTPSession};
    pub use data::{FTPDataConnection, FTPDataMode};
}

pub mod errors;
pub mod types;

pub use errors::{FTPError};
pub use types::{FTPCommand, FTPReply, FTPReplyCode, FTPDataType, FTPTransferMode, FTPState, FTPLimits};

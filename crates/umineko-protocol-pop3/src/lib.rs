//! POP3.

#![no_std]
#![allow(async_fn_in_trait)]

extern crate alloc;

pub mod api {
    pub mod client;
    pub mod server;

    pub use client::{POP3Client, POP3ClientConfig};
    pub use server::{POP3Server, POP3ServerConfig, POP3Handler};
}

pub mod helpers {
    pub mod apop;
    pub mod uidl;

    pub use apop::{APOPDigest};
    pub use uidl::{POP3UniqueID};
}

pub mod protocol {
    pub mod base;
    pub mod session;

    pub use base::{POP3Connection};
    pub use session::{POP3Session, POP3Maildrop, POP3Entry};
}

pub mod errors;
pub mod types;

pub use errors::{POP3Error};
pub use types::{POP3Command, POP3Response, POP3State, POP3Capability, POP3Limits};

//! SMTP.

#![no_std]
#![allow(async_fn_in_trait)]

extern crate alloc;

pub mod api {
    pub mod client;
    pub mod server;

    pub use client::{SMTPClient, SMTPClientConfig};
    pub use server::{SMTPServer, SMTPServerConfig, SMTPHandler};
}

pub mod helpers {
    pub mod mime;
    pub mod dsn;
    pub mod queue;

    pub use mime::{MIMEMessage, MIMEPart, MIMEEncoding};
    pub use dsn::{SMTPDeliveryStatus, SMTPDeliveryAction};
    pub use queue::{SMTPQueue, SMTPQueueEntry};
}

pub mod protocol {
    pub mod base;
    pub mod session;
    pub mod auth;

    pub use base::{SMTPConnection};
    pub use session::{SMTPSession, SMTPTransaction};
    pub use auth::{SMTPAuth, SMTPCredentials};
}

pub mod errors;
pub mod types;

pub use errors::{SMTPError};
pub use types::{SMTPCommand, SMTPReply, SMTPReplyCode, SMTPExtension, SMTPState, SMTPAddress, SMTPLimits};

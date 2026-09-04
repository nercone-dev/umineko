//! NTP.

#![no_std]
#![allow(async_fn_in_trait)]

extern crate alloc;

pub mod api {
    pub mod client;
    pub mod server;

    pub use client::{NTPClient, NTPClientConfig};
    pub use server::{NTPServer, NTPServerConfig, NTPHandler};
}

pub mod helpers {
    pub mod clock;

    pub use clock::{NTPClock, NTPSample};
}

pub mod protocol {
    pub mod base;
    pub mod v3;
    pub mod v4;

    pub use base::{NTPConnection, NTPPacket};
    pub use v3::{NTPV3Connection};
    pub use v4::{NTPV4Connection, NTPExtension};
}

pub mod errors;
pub mod types;

pub use errors::{NTPError};
pub use types::{NTPVersion, NTPMode, NTPStratum, NTPTimestamp, NTPLeapIndicator, NTPLimits};

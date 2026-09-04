//! Darwin provider.

#![cfg(target_vendor = "apple")]

extern crate alloc;

pub mod darwin;

#[cfg(feature = "ip")]
pub mod ip;
#[cfg(feature = "icmp")]
pub mod icmp;
#[cfg(feature = "uds")]
pub mod uds;
#[cfg(feature = "tcp")]
pub mod tcp;
#[cfg(feature = "udp")]
pub mod udp;
#[cfg(feature = "hash")]
pub mod hash;
#[cfg(feature = "crypto")]
pub mod crypto;
#[cfg(feature = "tls")]
pub mod tls;
#[cfg(feature = "quic")]
pub mod quic;

pub use darwin::{DarwinProvider};

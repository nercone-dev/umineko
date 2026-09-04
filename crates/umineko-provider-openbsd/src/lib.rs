//! OpenBSD provider.

#![cfg(target_os = "openbsd")]

extern crate alloc;

pub mod openbsd;

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

pub use openbsd::{OpenBSDProvider};

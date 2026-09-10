//! Android provider.

#![cfg(target_os = "android")]

extern crate alloc;

pub mod android;

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
#[cfg(feature = "crypto")]
pub mod crypto;

pub use android::{AndroidProvider};

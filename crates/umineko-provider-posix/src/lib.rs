//! POSIX provider.

#![cfg(unix)]

extern crate alloc;

pub mod posix;
pub mod errno;

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

pub use posix::{POSIXProvider};
pub use errno::{POSIXErrno};

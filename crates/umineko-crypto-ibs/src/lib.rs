//! Identity-based signatures (ISO/IEC 14888-3).

#![no_std]

extern crate alloc;

pub mod errors;
pub mod ibs;

pub use errors::{IBSError};
pub use ibs::{IBS, IBSMasterKey, IBSPublicParameters, IBSSigningKey, IBSSignature};

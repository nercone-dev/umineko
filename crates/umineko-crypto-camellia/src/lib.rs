//! Camellia.

#![no_std]
#![allow(non_camel_case_types)]

extern crate alloc;

pub mod errors;
pub mod camellia;

pub use errors::{CamelliaError};
pub use camellia::{Camellia, CamelliaMode, Camellia128, Camellia192, Camellia256};

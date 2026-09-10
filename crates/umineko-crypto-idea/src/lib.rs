//! IDEA.

#![no_std]

extern crate alloc;

pub mod errors;
pub mod idea;

pub use errors::{IDEAError};
pub use idea::{IDEAMode, IDEA};

//! GOST block ciphers: Kuznyechik, Magma and GOST 28147-89.

#![no_std]
#![allow(non_camel_case_types)]

extern crate alloc;

pub mod errors;
pub mod gost;
pub mod kuznyechik;
pub mod magma;
pub mod gost28147;

pub use errors::{GOSTError};
pub use gost::{GOSTMode};
pub use kuznyechik::{Kuznyechik};
pub use magma::{Magma};
pub use gost28147::{GOST28147, GOST28147Mode, GOST28147KeyMeshing, GOST28147SBox};

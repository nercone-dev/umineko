//! JWT.

#![no_std]
#![allow(non_camel_case_types)]

extern crate alloc;

pub mod jws;
pub mod jwe;
pub mod jwk;

pub mod errors;
pub mod types;

pub use errors::{JWTError};
pub use types::{JWT, JWTAlgorithm, JWTHeader, JWTClaims, JWTLimits};
pub use jws::{JWS, JWSSigner, JWSVerifier};
pub use jwe::{JWE, JWEAlgorithm, JWEEncryption};
pub use jwk::{JWK, JWKSet, JWKUse};

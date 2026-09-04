use alloc::{string::String, vec::Vec};
use crate::errors::SOCKSError;
use crate::types::SOCKSVersion;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SOCKSAuthentication {
    None,
    UsernamePassword,
    GSSAPI,
    Unacceptable,
    Unknown(u8),
}

impl SOCKSAuthentication {
    pub fn number(&self) -> u8 {
        todo!()
    }

    pub fn from_number(number: u8) -> Self {
        todo!()
    }

    pub fn allowed(&self, version: SOCKSVersion) -> bool {
        todo!()
    }

    pub fn plaintext(&self) -> bool {
        matches!(self, Self::UsernamePassword)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SOCKSCredentials {
    pub username: String,
    pub password: Option<String>,
}

impl SOCKSCredentials {
    pub const MAXIMUM_LENGTH: usize = 255;

    pub fn encode(&self, method: SOCKSAuthentication) -> Result<Vec<u8>, SOCKSError> {
        todo!()
    }

    pub fn decode(data: &[u8], method: SOCKSAuthentication) -> Result<(Self, usize), SOCKSError> {
        todo!()
    }
}

use alloc::{string::String, vec::Vec};
use crate::errors::SMTPError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SMTPAuth {
    Plain,
    Login,
    CRAMMD5,
    SCRAMSHA256,
    XOAUTH2,
}

impl SMTPAuth {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Plain => "PLAIN",
            Self::Login => "LOGIN",
            Self::CRAMMD5 => "CRAM-MD5",
            Self::SCRAMSHA256 => "SCRAM-SHA-256",
            Self::XOAUTH2 => "XOAUTH2",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        todo!()
    }

    pub fn requires_secure(&self) -> bool {
        matches!(self, Self::Plain | Self::Login | Self::XOAUTH2)
    }

    pub fn challenge_response(&self) -> bool {
        matches!(self, Self::CRAMMD5 | Self::SCRAMSHA256)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SMTPCredentials {
    pub username: String,
    pub password: Option<String>,
    pub token: Option<String>,
}

impl SMTPCredentials {
    pub fn initial(&self, mechanism: SMTPAuth) -> Result<Vec<u8>, SMTPError> {
        todo!()
    }

    pub fn respond(&self, mechanism: SMTPAuth, challenge: &[u8]) -> Result<Vec<u8>, SMTPError> {
        todo!()
    }
}

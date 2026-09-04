use alloc::{string::String, vec::Vec};
use crate::errors::SSHError;
use crate::helpers::key::SSHKey;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SSHAuthenticationMethod {
    None,
    PublicKey,
    Password,
    KeyboardInteractive,
    HostBased,
    GSSAPI,
}

impl SSHAuthenticationMethod {
    pub fn as_str(&self) -> &'static str {
        todo!()
    }

    pub fn from_name(name: &str) -> Option<Self> {
        todo!()
    }

    pub fn plaintext_secret(&self) -> bool {
        matches!(self, Self::Password)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SSHAuthentication {
    pub username: String,
    pub method: SSHAuthenticationMethod,
    pub password: Option<String>,
    pub key: Option<SSHKey>,
    pub attempts: u8,
    pub available: Vec<SSHAuthenticationMethod>,
}

impl SSHAuthentication {
    pub fn sign(&self, session_id: &[u8], private: &[u8]) -> Result<Vec<u8>, SSHError> {
        todo!()
    }

    pub fn verify(&self, session_id: &[u8], signature: &[u8]) -> Result<(), SSHError> {
        todo!()
    }

    pub fn next(&self) -> Option<SSHAuthenticationMethod> {
        todo!()
    }

    pub fn encode(&self) -> Result<Vec<u8>, SSHError> {
        todo!()
    }

    pub fn decode(data: &[u8]) -> Result<Self, SSHError> {
        todo!()
    }
}

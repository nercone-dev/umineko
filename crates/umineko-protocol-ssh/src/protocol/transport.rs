use alloc::vec::Vec;
use crate::errors::SSHError;
use crate::types::{SSHVersion, SSHRole, SSHLimits};
use crate::helpers::kex::{SSHKeyExchange, SSHKeyExchangeState};
use crate::helpers::cipher::SSHCipher;
use crate::helpers::mac::{SSHMac, SSHCompression};
use crate::helpers::key::SSHKey;

#[derive(Debug, Clone, PartialEq)]
pub struct SSHTransport {
    version: SSHVersion,
    role: SSHRole,
    state: SSHKeyExchangeState,

    key_exchange: Option<SSHKeyExchange>,
    cipher: Option<SSHCipher>,
    mac: Option<SSHMac>,
    compression: Option<SSHCompression>,
    host_key: Option<SSHKey>,

    session_id: Option<Vec<u8>>,
    send_sequence: u32,
    receive_sequence: u32,
    sent_bytes: u64,
    limits: SSHLimits,
}

impl SSHTransport {
    pub fn new(role: SSHRole, limits: SSHLimits) -> Self {
        todo!()
    }

    pub fn state(&self) -> SSHKeyExchangeState {
        self.state
    }

    pub fn session_id(&self) -> Option<&[u8]> {
        todo!()
    }

    pub fn propose(&self) -> Result<Vec<u8>, SSHError> {
        todo!()
    }

    pub fn negotiate(&mut self, peer: &[u8]) -> Result<(), SSHError> {
        todo!()
    }

    pub fn derive(&mut self, shared: &[u8], hash: &[u8]) -> Result<(), SSHError> {
        todo!()
    }

    pub fn activate(&mut self) -> Result<(), SSHError> {
        todo!()
    }

    pub fn should_refresh(&self) -> bool {
        todo!()
    }
}

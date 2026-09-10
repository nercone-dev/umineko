use alloc::vec::Vec;
use crate::errors::{SSHError, SSHDisconnectReason};
use crate::types::{SSHVersion, SSHRole, SSHMessageType, SSHLimits};
use crate::helpers::cipher::SSHCipher;
use crate::helpers::kex::SSHKeyExchange;
use crate::helpers::key::SSHKey;
use crate::protocol::connection::{SSHChannel, SSHChannelType};
use crate::protocol::transport::SSHTransport;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SSHPacket {
    pub kind: SSHMessageType,
    pub payload: Vec<u8>,
}

impl SSHPacket {
    pub const HEADER_SIZE: usize = 5;
    pub const MINIMUM_BLOCK_SIZE: usize = 8;

    pub fn encode(&self, limits: SSHLimits) -> Result<Vec<u8>, SSHError> {
        todo!()
    }

    pub fn decode(data: &[u8], limits: SSHLimits) -> Result<(Self, usize), SSHError> {
        todo!()
    }
}

#[derive(Debug)]
pub struct SSHConnection {
    transport: SSHTransport,
    role: SSHRole,
    authenticated: bool,
    limits: SSHLimits,
}

impl SSHConnection {
    pub fn version(&self) -> SSHVersion {
        todo!()
    }

    pub fn role(&self) -> SSHRole {
        self.role
    }

    pub fn limits(&self) -> SSHLimits {
        self.limits
    }

    pub fn transport(&self) -> &SSHTransport {
        &self.transport
    }

    pub fn key_exchange(&self) -> Option<SSHKeyExchange> {
        todo!()
    }

    pub fn cipher(&self) -> Option<SSHCipher> {
        todo!()
    }

    pub fn host_key(&self) -> Option<&SSHKey> {
        todo!()
    }

    pub fn authenticated(&self) -> bool {
        self.authenticated
    }

    pub async fn handshake(&mut self) -> Result<(), SSHError> {
        todo!()
    }

    pub async fn send(&mut self, packet: &SSHPacket) -> Result<(), SSHError> {
        todo!()
    }

    pub async fn receive(&mut self) -> Result<SSHPacket, SSHError> {
        todo!()
    }

    pub async fn open(&mut self, kind: SSHChannelType) -> Result<SSHChannel, SSHError> {
        todo!()
    }

    pub async fn accept(&mut self) -> Result<SSHChannel, SSHError> {
        todo!()
    }

    pub fn channel(&mut self, id: u32) -> Option<&mut SSHChannel> {
        todo!()
    }

    pub async fn grant(&mut self) -> Result<(), SSHError> {
        todo!()
    }

    pub async fn deny(&mut self) -> Result<(), SSHError> {
        todo!()
    }

    pub async fn refresh(&mut self) -> Result<(), SSHError> {
        todo!()
    }

    pub async fn disconnect(&mut self, reason: SSHDisconnectReason) -> Result<(), SSHError> {
        todo!()
    }
}

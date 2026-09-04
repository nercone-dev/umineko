use alloc::{string::String, vec::Vec};
use crate::errors::SSHError;
use crate::types::SSHLimits;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SSHChannelType {
    Session,
    ForwardedTCPIP { address: String, port: u16 },
    DirectTCPIP { address: String, port: u16 },
    DirectStreamLocal(String),
    Unknown(String),
}

impl SSHChannelType {
    pub fn as_str(&self) -> &str {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SSHChannelRequest {
    Pty { term: String, columns: u32, rows: u32, modes: Vec<u8> },
    Env { name: String, value: String },
    Shell,
    Exec(String),
    Subsystem(String),
    WindowChange { columns: u32, rows: u32 },
    Signal(String),
    ExitStatus(u32),
    Unknown { name: String, data: Vec<u8> },
}

impl SSHChannelRequest {
    pub fn as_str(&self) -> &str {
        todo!()
    }

    pub fn wants_reply(&self) -> bool {
        todo!()
    }
}

#[derive(Debug)]
pub struct SSHChannel {
    id: u32,
    peer_id: u32,
    kind: SSHChannelType,
    window: u32,
    peer_window: u32,
    max_packet_size: u32,
    sent_eof: bool,
    received_eof: bool,
    limits: SSHLimits,
}

impl SSHChannel {
    pub fn id(&self) -> u32 {
        self.id
    }

    pub fn kind(&self) -> &SSHChannelType {
        &self.kind
    }

    pub fn sendable(&self) -> u32 {
        self.peer_window
    }

    pub async fn send(&mut self, data: &[u8]) -> Result<usize, SSHError> {
        todo!()
    }

    pub async fn send_extended(&mut self, kind: u32, data: &[u8]) -> Result<usize, SSHError> {
        todo!()
    }

    pub async fn receive(&mut self, data: &mut [u8]) -> Result<usize, SSHError> {
        todo!()
    }

    pub async fn request(&mut self, request: SSHChannelRequest) -> Result<(), SSHError> {
        todo!()
    }

    pub async fn adjust(&mut self, size: u32) -> Result<(), SSHError> {
        todo!()
    }

    pub async fn eof(&mut self) -> Result<(), SSHError> {
        todo!()
    }

    pub async fn close(&mut self) -> Result<(), SSHError> {
        todo!()
    }
}

use alloc::vec::Vec;
use crate::errors::TLSError;
use crate::types::{TLSVersion, TLSRole, TLSCipher, TLSGroup, TLSExtension, TLSLimits};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TLSHandshakeType {
    ClientHello,
    ServerHello,
    HelloRetryRequest,
    NewSessionTicket,
    EndOfEarlyData,
    EncryptedExtensions,
    Certificate,
    CertificateRequest,
    CertificateVerify,
    Finished,
    KeyUpdate,
    Unknown(u8),
}

impl TLSHandshakeType {
    pub fn number(&self) -> u8 {
        todo!()
    }

    pub fn from_number(number: u8) -> Self {
        todo!()
    }

    pub fn allowed(&self, version: TLSVersion) -> bool {
        todo!()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TLSHandshakeState {
    Initial,
    Waiting,
    Verifying,
    Established,
    Retrying,
    Failed,
    Closed,
}

impl TLSHandshakeState {
    pub fn established(&self) -> bool {
        matches!(self, Self::Established)
    }

    pub fn terminal(&self) -> bool {
        matches!(self, Self::Failed | Self::Closed)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TLSHandshake {
    pub kind: TLSHandshakeType,
    pub version: TLSVersion,
    pub random: [u8; 32],
    pub session: Vec<u8>,
    pub ciphers: Vec<TLSCipher>,
    pub groups: Vec<TLSGroup>,
    pub extensions: Vec<TLSExtension>,
}

impl TLSHandshake {
    pub const HEADER_SIZE: usize = 4;

    pub fn extension(&self, kind: u16) -> Option<&TLSExtension> {
        todo!()
    }

    pub fn encode(&self) -> Result<Vec<u8>, TLSError> {
        todo!()
    }

    pub fn decode(data: &[u8], role: TLSRole, limits: TLSLimits) -> Result<(Self, usize), TLSError> {
        todo!()
    }
}

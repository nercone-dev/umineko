use alloc::vec::Vec;
use crate::errors::QUICError;
use crate::types::{QUICVersion, QUICRole, QUICTransportParameters};

use umineko_protocol_tls::{TLSVersion, TLSCipher};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum QUICEncryptionLevel {
    Initial,
    ZeroRTT,
    Handshake,
    ApplicationData,
}

impl QUICEncryptionLevel {
    pub fn packet_type(&self) -> &'static str {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct QUICHandshake {
    version: QUICVersion,
    role: QUICRole,
    level: QUICEncryptionLevel,
    cipher: Option<TLSCipher>,
    parameters: QUICTransportParameters,
}

impl QUICHandshake {
    pub const TLS_VERSION: TLSVersion = TLSVersion::V1_3;

    pub fn new(version: QUICVersion, role: QUICRole, parameters: QUICTransportParameters) -> Self {
        todo!()
    }

    pub fn level(&self) -> QUICEncryptionLevel {
        self.level
    }

    pub fn cipher(&self) -> Option<TLSCipher> {
        self.cipher
    }

    pub fn initial_keys(&self, destination: &[u8]) -> Result<(Vec<u8>, Vec<u8>), QUICError> {
        todo!()
    }

    pub fn emit(&mut self) -> Result<Option<(QUICEncryptionLevel, Vec<u8>)>, QUICError> {
        todo!()
    }

    pub fn absorb(&mut self, level: QUICEncryptionLevel, data: &[u8]) -> Result<(), QUICError> {
        todo!()
    }

    pub fn peer_parameters(&self) -> Option<&QUICTransportParameters> {
        todo!()
    }

    pub fn established(&self) -> bool {
        todo!()
    }
}

use crate::errors::HTTPError;
use crate::types::{HTTPVersion, HTTPRole, HTTPStreamID, HTTPConnectionID, HTTPMessage, HTTPLimits};
use crate::protocol::stream::HTTPStream;
use crate::helpers::qpack::QPACK;

use umineko_protocol_tls::{TLSVersion, TLSCipher};
use umineko_protocol_quic::QUICVersion;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum H3Setting {
    MaxFieldSectionSize(u64),
    QPACKMaxTableCapacity(u64),
    QPACKBlockedStreams(u64),
    EnableConnectProtocol(bool),
    Unknown { kind: u64, value: u64 },
}

impl H3Setting {
    pub fn kind(&self) -> u64 {
        todo!()
    }

    pub fn value(&self) -> u64 {
        todo!()
    }

    pub fn from_pair(kind: u64, value: u64) -> Self {
        todo!()
    }
}

#[derive(Debug)]
pub struct H3Connection {
    role: HTTPRole,
    id: HTTPConnectionID,
    qpack: QPACK,
    limits: HTTPLimits,
}

impl H3Connection {
    pub const VERSION: HTTPVersion = HTTPVersion::V3_0;

    pub fn new(role: HTTPRole, limits: HTTPLimits) -> Self {
        todo!()
    }

    pub fn version(&self) -> HTTPVersion {
        Self::VERSION
    }

    pub fn role(&self) -> HTTPRole {
        self.role
    }

    pub fn id(&self) -> &HTTPConnectionID {
        &self.id
    }

    pub fn limits(&self) -> HTTPLimits {
        self.limits
    }

    pub fn secure(&self) -> bool {
        true
    }

    pub fn tls_version(&self) -> Option<TLSVersion> {
        todo!()
    }

    pub fn tls_cipher(&self) -> Option<TLSCipher> {
        todo!()
    }

    pub fn multiplexed(&self) -> bool {
        true
    }

    pub fn stream_count(&self) -> usize {
        todo!()
    }

    pub async fn open(&mut self) -> Result<HTTPStream, HTTPError> {
        todo!()
    }

    pub async fn accept(&mut self) -> Result<HTTPStream, HTTPError> {
        todo!()
    }

    pub fn stream(&mut self, id: HTTPStreamID) -> Option<&mut HTTPStream> {
        todo!()
    }

    pub async fn drain(&mut self) -> Result<(), HTTPError> {
        todo!()
    }

    pub async fn ping(&mut self) -> Result<f64, HTTPError> {
        todo!()
    }

    pub async fn close(&mut self) -> Result<(), HTTPError> {
        todo!()
    }

    pub fn quic_version(&self) -> QUICVersion {
        todo!()
    }

    pub fn settings(&self) -> &[H3Setting] {
        todo!()
    }

    pub async fn update_settings(&mut self, settings: &[H3Setting]) -> Result<(), HTTPError> {
        todo!()
    }

    pub async fn push(&mut self, stream: HTTPStreamID, message: HTTPMessage) -> Result<HTTPStream, HTTPError> {
        todo!()
    }

    pub async fn prioritize(&mut self, stream: HTTPStreamID, urgency: u8, incremental: bool) -> Result<(), HTTPError> {
        todo!()
    }
}

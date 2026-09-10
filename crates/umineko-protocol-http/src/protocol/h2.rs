use crate::errors::HTTPError;
use crate::types::{HTTPVersion, HTTPRole, HTTPStreamID, HTTPConnectionID, HTTPMessage, HTTPLimits};
use crate::protocol::stream::HTTPStream;
use crate::helpers::hpack::HPACK;

use umineko_protocol_tls::{TLSVersion, TLSCipher};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum H2Setting {
    HeaderTableSize(u32),
    EnablePush(bool),
    MaxConcurrentStreams(u32),
    InitialWindowSize(u32),
    MaxFrameSize(u32),
    MaxHeaderListSize(u32),
    Unknown { kind: u16, value: u32 },
}

impl H2Setting {
    pub fn kind(&self) -> u16 {
        todo!()
    }

    pub fn value(&self) -> u32 {
        todo!()
    }

    pub fn from_pair(kind: u16, value: u32) -> Self {
        todo!()
    }
}

#[derive(Debug)]
pub struct H2Connection {
    role: HTTPRole,
    id: HTTPConnectionID,
    hpack: HPACK,
    limits: HTTPLimits,
}

impl H2Connection {
    pub const VERSION: HTTPVersion = HTTPVersion::V2_0;
    pub const PREFACE: &'static [u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

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
        todo!()
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

    pub fn settings(&self) -> &[H2Setting] {
        todo!()
    }

    pub async fn update_settings(&mut self, settings: &[H2Setting]) -> Result<(), HTTPError> {
        todo!()
    }

    pub async fn push(&mut self, stream: HTTPStreamID, message: HTTPMessage) -> Result<HTTPStream, HTTPError> {
        todo!()
    }

    pub async fn prioritize(&mut self, stream: HTTPStreamID, urgency: u8, incremental: bool) -> Result<(), HTTPError> {
        todo!()
    }
}

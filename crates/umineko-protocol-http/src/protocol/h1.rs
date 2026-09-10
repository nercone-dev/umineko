use crate::errors::HTTPError;
use crate::types::{HTTPVersion, HTTPRole, HTTPStreamID, HTTPConnectionID, HTTPLimits};
use crate::protocol::stream::HTTPStream;

use umineko_protocol_tls::{TLSVersion, TLSCipher};

#[derive(Debug)]
pub struct H1Connection {
    version: HTTPVersion,
    role: HTTPRole,
    id: HTTPConnectionID,
    limits: HTTPLimits,
}

impl H1Connection {
    pub fn new(version: HTTPVersion, role: HTTPRole, limits: HTTPLimits) -> Self {
        todo!()
    }

    pub fn version(&self) -> HTTPVersion {
        self.version
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
        false
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

    pub fn pipelining(&self) -> bool {
        todo!()
    }

    pub fn keepalive(&self) -> bool {
        todo!()
    }

    pub fn chunked(&self, stream: HTTPStreamID) -> bool {
        todo!()
    }

    pub async fn upgrade(&mut self, protocol: &str) -> Result<(), HTTPError> {
        todo!()
    }
}

use crate::errors::HTTPError;
use crate::types::{HTTPVersion, HTTPStreamID, HTTPHeaders, HTTPMessage, HTTPLimits};
#[cfg(feature = "websocket")]
use crate::protocol::ws::WSConnection;

///
#[derive(Debug)]
pub struct HTTPStream {
    id: HTTPStreamID,
    version: HTTPVersion,
    limits: HTTPLimits,
}

impl HTTPStream {
    pub fn id(&self) -> HTTPStreamID {
        self.id
    }

    pub fn version(&self) -> HTTPVersion {
        self.version
    }

    pub fn limits(&self) -> HTTPLimits {
        self.limits
    }

    pub fn closed(&self) -> bool {
        todo!()
    }

    pub async fn send(&mut self, message: HTTPMessage) -> Result<(), HTTPError> {
        todo!()
    }

    pub async fn send_body(&mut self, chunk: &[u8], last: bool) -> Result<usize, HTTPError> {
        todo!()
    }

    pub async fn send_trailers(&mut self, trailers: HTTPHeaders) -> Result<(), HTTPError> {
        todo!()
    }

    pub async fn receive(&mut self) -> Result<HTTPMessage, HTTPError> {
        todo!()
    }

    pub async fn receive_body(&mut self, chunk: &mut [u8]) -> Result<usize, HTTPError> {
        todo!()
    }

    pub async fn cancel(&mut self) -> Result<(), HTTPError> {
        todo!()
    }

    #[cfg(feature = "websocket")]
    pub async fn upgrade(self) -> Result<WSConnection, HTTPError> {
        todo!()
    }
}

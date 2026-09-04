use crate::errors::HTTPError;
use crate::types::{HTTPVersion, HTTPRole, HTTPStreamID, HTTPConnectionID, HTTPLimits};
use crate::protocol::stream::HTTPStream;

use umineko_protocol_tls::{TLSVersion, TLSCipher};

///
#[derive(Debug)]
pub enum HTTPConnection {
    #[cfg(any(feature = "http10", feature = "http11"))]
    H1(crate::protocol::h1::H1Connection),
    #[cfg(feature = "http20")]
    H2(crate::protocol::h2::H2Connection),
    #[cfg(feature = "http30")]
    H3(crate::protocol::h3::H3Connection),
}

impl HTTPConnection {
    pub fn version(&self) -> HTTPVersion {
        todo!()
    }

    pub fn role(&self) -> HTTPRole {
        todo!()
    }

    pub fn id(&self) -> &HTTPConnectionID {
        todo!()
    }

    pub fn limits(&self) -> HTTPLimits {
        todo!()
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
        todo!()
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
}

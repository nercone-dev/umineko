use alloc::{sync::Arc, vec::Vec};
use crate::errors::{QUICError, QUICTransportError};
use crate::types::{QUICVersion, QUICRole, QUICConnectionID, QUICStreamID, QUICTransportParameters, QUICLimits};
use crate::protocol::stream::QUICStream;
use crate::provider::QUICProvider;

use umineko_helpers::provider::ProviderHandle;

///
#[derive(Debug)]
pub enum QUICConnection {
    V1(crate::protocol::v1::QUICV1Connection),
    V2(crate::protocol::v2::QUICV2Connection),
}

impl QUICConnection {
    pub fn from_provider(provider: Arc<dyn QUICProvider>, handle: ProviderHandle, limits: QUICLimits) -> Result<Self, QUICError> {
        let version = match provider.version(handle) {
            Ok(version) => version,
            Err(error) => {
                provider.release(handle);
                return Err(error.into());
            }
        };
        match version {
            QUICVersion::V1 => Ok(Self::V1(crate::protocol::v1::QUICV1Connection::from_provider(provider, handle, limits)?)),
            QUICVersion::V2 => Ok(Self::V2(crate::protocol::v2::QUICV2Connection::from_provider(provider, handle, limits)?)),
        }
    }

    pub fn supported_versions() -> Vec<QUICVersion> {
        todo!()
    }

    pub fn provider(&self) -> Option<&Arc<dyn QUICProvider>> {
        match *self {
            Self::V1(ref connection) => connection.provider(),
            Self::V2(ref connection) => connection.provider(),
        }
    }

    pub fn version(&self) -> QUICVersion {
        match *self {
            Self::V1(ref connection) => connection.version(),
            Self::V2(ref connection) => connection.version(),
        }
    }

    pub fn role(&self) -> QUICRole {
        match *self {
            Self::V1(ref connection) => connection.role(),
            Self::V2(ref connection) => connection.role(),
        }
    }

    pub fn local_id(&self) -> &QUICConnectionID {
        match *self {
            Self::V1(ref connection) => connection.local_id(),
            Self::V2(ref connection) => connection.local_id(),
        }
    }

    pub fn remote_id(&self) -> &QUICConnectionID {
        match *self {
            Self::V1(ref connection) => connection.remote_id(),
            Self::V2(ref connection) => connection.remote_id(),
        }
    }

    pub fn parameters(&self) -> &QUICTransportParameters {
        match *self {
            Self::V1(ref connection) => connection.parameters(),
            Self::V2(ref connection) => connection.parameters(),
        }
    }

    pub fn limits(&self) -> QUICLimits {
        match *self {
            Self::V1(ref connection) => connection.limits(),
            Self::V2(ref connection) => connection.limits(),
        }
    }

    pub fn application_protocol(&self) -> Option<&str> {
        match *self {
            Self::V1(ref connection) => connection.application_protocol(),
            Self::V2(ref connection) => connection.application_protocol(),
        }
    }

    pub fn established(&self) -> bool {
        match *self {
            Self::V1(ref connection) => connection.established(),
            Self::V2(ref connection) => connection.established(),
        }
    }

    pub fn absorb(&mut self, datagram: &[u8]) -> Result<(), QUICError> {
        match *self {
            Self::V1(ref mut connection) => connection.absorb(datagram),
            Self::V2(ref mut connection) => connection.absorb(datagram),
        }
    }

    pub fn emit(&mut self, output: &mut Vec<u8>) -> Result<usize, QUICError> {
        match *self {
            Self::V1(ref mut connection) => connection.emit(output),
            Self::V2(ref mut connection) => connection.emit(output),
        }
    }

    pub fn timeout(&self) -> Result<Option<f64>, QUICError> {
        match *self {
            Self::V1(ref connection) => connection.timeout(),
            Self::V2(ref connection) => connection.timeout(),
        }
    }

    pub fn step(&mut self) -> Result<bool, QUICError> {
        match *self {
            Self::V1(ref mut connection) => connection.step(),
            Self::V2(ref mut connection) => connection.step(),
        }
    }

    pub async fn handshake(&mut self) -> Result<(), QUICError> {
        match *self {
            Self::V1(ref mut connection) => connection.handshake().await,
            Self::V2(ref mut connection) => connection.handshake().await,
        }
    }

    pub async fn open(&mut self, bidirectional: bool) -> Result<QUICStream, QUICError> {
        match *self {
            Self::V1(ref mut connection) => connection.open(bidirectional).await,
            Self::V2(ref mut connection) => connection.open(bidirectional).await,
        }
    }

    pub async fn accept(&mut self) -> Result<QUICStream, QUICError> {
        match *self {
            Self::V1(ref mut connection) => connection.accept().await,
            Self::V2(ref mut connection) => connection.accept().await,
        }
    }

    pub fn stream(&mut self, id: QUICStreamID) -> Option<&mut QUICStream> {
        match *self {
            Self::V1(ref mut connection) => connection.stream(id),
            Self::V2(ref mut connection) => connection.stream(id),
        }
    }

    pub async fn probe(&mut self) -> Result<(), QUICError> {
        match *self {
            Self::V1(ref mut connection) => connection.probe().await,
            Self::V2(ref mut connection) => connection.probe().await,
        }
    }

    pub async fn migrate(&mut self) -> Result<(), QUICError> {
        match *self {
            Self::V1(ref mut connection) => connection.migrate().await,
            Self::V2(ref mut connection) => connection.migrate().await,
        }
    }

    pub async fn refresh(&mut self) -> Result<(), QUICError> {
        match *self {
            Self::V1(ref mut connection) => connection.refresh().await,
            Self::V2(ref mut connection) => connection.refresh().await,
        }
    }

    pub async fn close(&mut self, error: QUICTransportError, reason: &[u8]) -> Result<(), QUICError> {
        match *self {
            Self::V1(ref mut connection) => connection.close(error, reason).await,
            Self::V2(ref mut connection) => connection.close(error, reason).await,
        }
    }
}

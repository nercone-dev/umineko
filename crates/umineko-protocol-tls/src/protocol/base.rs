use alloc::{sync::Arc, vec::Vec};
use crate::errors::{TLSError, TLSAlert};
use crate::types::{TLSVersion, TLSRole, TLSGroup, TLSCipher, TLSLimits};
use crate::helpers::certificate::TLSCertificateChain;
use crate::helpers::alpn::TLSApplicationProtocol;
use crate::helpers::handshake::TLSHandshakeState;
use crate::provider::TLSProvider;

use umineko_helpers::provider::ProviderHandle;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TLSContentType {
    ChangeCipherSpec,
    Alert,
    Handshake,
    ApplicationData,
    Unknown(u8),
}

impl TLSContentType {
    pub fn number(&self) -> u8 {
        todo!()
    }

    pub fn from_number(number: u8) -> Self {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TLSRecord {
    pub content: TLSContentType,
    pub version: TLSVersion,
    pub payload: Vec<u8>,
}

impl TLSRecord {
    pub const HEADER_SIZE: usize = 5;
    pub const MAXIMUM_PAYLOAD_SIZE: usize = 16 * 1024;

    pub fn encode(&self) -> Result<Vec<u8>, TLSError> {
        todo!()
    }

    pub fn decode(data: &[u8], limits: TLSLimits) -> Result<(Self, usize), TLSError> {
        todo!()
    }
}

///
#[derive(Debug)]
pub enum TLSConnection {
    #[cfg(feature = "tls10")]
    V1_0(crate::protocol::tls10::TLS10Connection),
    #[cfg(feature = "tls11")]
    V1_1(crate::protocol::tls11::TLS11Connection),
    #[cfg(feature = "tls12")]
    V1_2(crate::protocol::tls12::TLS12Connection),
    #[cfg(feature = "tls13")]
    V1_3(crate::protocol::tls13::TLS13Connection),
    #[cfg(feature = "dtls")]
    DTLS(crate::protocol::dtls::DTLSConnection),
}

impl TLSConnection {
    pub fn from_provider(provider: Arc<dyn TLSProvider>, handle: ProviderHandle, limits: TLSLimits) -> Result<Self, TLSError> {
        let version = match provider.version(handle) {
            Ok(Some(version)) => version,
            Ok(None) => {
                provider.release(handle);
                return Err(TLSError::Version);
            }
            Err(error) => {
                provider.release(handle);
                return Err(error.into());
            }
        };
        match version {
            #[cfg(feature = "tls10")]
            TLSVersion::V1_0 => Ok(Self::V1_0(crate::protocol::tls10::TLS10Connection::from_provider(provider, handle, limits)?)),
            #[cfg(feature = "tls11")]
            TLSVersion::V1_1 => Ok(Self::V1_1(crate::protocol::tls11::TLS11Connection::from_provider(provider, handle, limits)?)),
            #[cfg(feature = "tls12")]
            TLSVersion::V1_2 => Ok(Self::V1_2(crate::protocol::tls12::TLS12Connection::from_provider(provider, handle, limits)?)),
            #[cfg(feature = "tls13")]
            TLSVersion::V1_3 => Ok(Self::V1_3(crate::protocol::tls13::TLS13Connection::from_provider(provider, handle, limits)?)),
            #[allow(unreachable_patterns)]
            _ => {
                provider.release(handle);
                Err(TLSError::Version)
            }
        }
    }

    pub fn provider(&self) -> Option<&Arc<dyn TLSProvider>> {
        match *self {
            #[cfg(feature = "tls10")]
            Self::V1_0(ref connection) => connection.provider(),
            #[cfg(feature = "tls11")]
            Self::V1_1(ref connection) => connection.provider(),
            #[cfg(feature = "tls12")]
            Self::V1_2(ref connection) => connection.provider(),
            #[cfg(feature = "tls13")]
            Self::V1_3(ref connection) => connection.provider(),
            #[cfg(feature = "dtls")]
            Self::DTLS(ref connection) => connection.provider(),
        }
    }

    pub fn version(&self) -> TLSVersion {
        match *self {
            #[cfg(feature = "tls10")]
            Self::V1_0(ref connection) => connection.version(),
            #[cfg(feature = "tls11")]
            Self::V1_1(ref connection) => connection.version(),
            #[cfg(feature = "tls12")]
            Self::V1_2(ref connection) => connection.version(),
            #[cfg(feature = "tls13")]
            Self::V1_3(ref connection) => connection.version(),
            #[cfg(feature = "dtls")]
            Self::DTLS(ref connection) => connection.version(),
        }
    }

    pub fn role(&self) -> TLSRole {
        match *self {
            #[cfg(feature = "tls10")]
            Self::V1_0(ref connection) => connection.role(),
            #[cfg(feature = "tls11")]
            Self::V1_1(ref connection) => connection.role(),
            #[cfg(feature = "tls12")]
            Self::V1_2(ref connection) => connection.role(),
            #[cfg(feature = "tls13")]
            Self::V1_3(ref connection) => connection.role(),
            #[cfg(feature = "dtls")]
            Self::DTLS(ref connection) => connection.role(),
        }
    }

    pub fn state(&self) -> TLSHandshakeState {
        match *self {
            #[cfg(feature = "tls10")]
            Self::V1_0(ref connection) => connection.state(),
            #[cfg(feature = "tls11")]
            Self::V1_1(ref connection) => connection.state(),
            #[cfg(feature = "tls12")]
            Self::V1_2(ref connection) => connection.state(),
            #[cfg(feature = "tls13")]
            Self::V1_3(ref connection) => connection.state(),
            #[cfg(feature = "dtls")]
            Self::DTLS(ref connection) => connection.state(),
        }
    }

    pub fn cipher(&self) -> Option<TLSCipher> {
        match *self {
            #[cfg(feature = "tls10")]
            Self::V1_0(ref connection) => connection.cipher(),
            #[cfg(feature = "tls11")]
            Self::V1_1(ref connection) => connection.cipher(),
            #[cfg(feature = "tls12")]
            Self::V1_2(ref connection) => connection.cipher(),
            #[cfg(feature = "tls13")]
            Self::V1_3(ref connection) => connection.cipher(),
            #[cfg(feature = "dtls")]
            Self::DTLS(ref connection) => connection.cipher(),
        }
    }

    pub fn group(&self) -> Option<TLSGroup> {
        match *self {
            #[cfg(feature = "tls10")]
            Self::V1_0(ref connection) => connection.group(),
            #[cfg(feature = "tls11")]
            Self::V1_1(ref connection) => connection.group(),
            #[cfg(feature = "tls12")]
            Self::V1_2(ref connection) => connection.group(),
            #[cfg(feature = "tls13")]
            Self::V1_3(ref connection) => connection.group(),
            #[cfg(feature = "dtls")]
            Self::DTLS(ref connection) => connection.group(),
        }
    }

    pub fn limits(&self) -> TLSLimits {
        match *self {
            #[cfg(feature = "tls10")]
            Self::V1_0(ref connection) => connection.limits(),
            #[cfg(feature = "tls11")]
            Self::V1_1(ref connection) => connection.limits(),
            #[cfg(feature = "tls12")]
            Self::V1_2(ref connection) => connection.limits(),
            #[cfg(feature = "tls13")]
            Self::V1_3(ref connection) => connection.limits(),
            #[cfg(feature = "dtls")]
            Self::DTLS(ref connection) => connection.limits(),
        }
    }

    pub fn peer_certificates(&self) -> Option<&TLSCertificateChain> {
        match *self {
            #[cfg(feature = "tls10")]
            Self::V1_0(ref connection) => connection.peer_certificates(),
            #[cfg(feature = "tls11")]
            Self::V1_1(ref connection) => connection.peer_certificates(),
            #[cfg(feature = "tls12")]
            Self::V1_2(ref connection) => connection.peer_certificates(),
            #[cfg(feature = "tls13")]
            Self::V1_3(ref connection) => connection.peer_certificates(),
            #[cfg(feature = "dtls")]
            Self::DTLS(ref connection) => connection.peer_certificates(),
        }
    }

    pub fn application_protocol(&self) -> Option<&str> {
        match *self {
            #[cfg(feature = "tls10")]
            Self::V1_0(ref connection) => connection.application_protocol(),
            #[cfg(feature = "tls11")]
            Self::V1_1(ref connection) => connection.application_protocol(),
            #[cfg(feature = "tls12")]
            Self::V1_2(ref connection) => connection.application_protocol(),
            #[cfg(feature = "tls13")]
            Self::V1_3(ref connection) => connection.application_protocol(),
            #[cfg(feature = "dtls")]
            Self::DTLS(ref connection) => connection.application_protocol(),
        }
    }

    pub fn server_name(&self) -> Option<&str> {
        match *self {
            #[cfg(feature = "tls10")]
            Self::V1_0(ref connection) => connection.server_name(),
            #[cfg(feature = "tls11")]
            Self::V1_1(ref connection) => connection.server_name(),
            #[cfg(feature = "tls12")]
            Self::V1_2(ref connection) => connection.server_name(),
            #[cfg(feature = "tls13")]
            Self::V1_3(ref connection) => connection.server_name(),
            #[cfg(feature = "dtls")]
            Self::DTLS(ref connection) => connection.server_name(),
        }
    }

    pub fn resumed(&self) -> bool {
        match *self {
            #[cfg(feature = "tls10")]
            Self::V1_0(ref connection) => connection.resumed(),
            #[cfg(feature = "tls11")]
            Self::V1_1(ref connection) => connection.resumed(),
            #[cfg(feature = "tls12")]
            Self::V1_2(ref connection) => connection.resumed(),
            #[cfg(feature = "tls13")]
            Self::V1_3(ref connection) => connection.resumed(),
            #[cfg(feature = "dtls")]
            Self::DTLS(ref connection) => connection.resumed(),
        }
    }

    pub fn select_certificate(&mut self, chain: TLSCertificateChain) -> Result<(), TLSError> {
        match *self {
            #[cfg(feature = "tls10")]
            Self::V1_0(ref mut connection) => connection.select_certificate(chain),
            #[cfg(feature = "tls11")]
            Self::V1_1(ref mut connection) => connection.select_certificate(chain),
            #[cfg(feature = "tls12")]
            Self::V1_2(ref mut connection) => connection.select_certificate(chain),
            #[cfg(feature = "tls13")]
            Self::V1_3(ref mut connection) => connection.select_certificate(chain),
            #[cfg(feature = "dtls")]
            Self::DTLS(ref mut connection) => connection.select_certificate(chain),
        }
    }

    pub fn select_application_protocol(&mut self, protocol: TLSApplicationProtocol) -> Result<(), TLSError> {
        match *self {
            #[cfg(feature = "tls10")]
            Self::V1_0(ref mut connection) => connection.select_application_protocol(protocol),
            #[cfg(feature = "tls11")]
            Self::V1_1(ref mut connection) => connection.select_application_protocol(protocol),
            #[cfg(feature = "tls12")]
            Self::V1_2(ref mut connection) => connection.select_application_protocol(protocol),
            #[cfg(feature = "tls13")]
            Self::V1_3(ref mut connection) => connection.select_application_protocol(protocol),
            #[cfg(feature = "dtls")]
            Self::DTLS(ref mut connection) => connection.select_application_protocol(protocol),
        }
    }

    pub fn absorb(&mut self, data: &[u8]) -> Result<usize, TLSError> {
        match *self {
            #[cfg(feature = "tls10")]
            Self::V1_0(ref mut connection) => connection.absorb(data),
            #[cfg(feature = "tls11")]
            Self::V1_1(ref mut connection) => connection.absorb(data),
            #[cfg(feature = "tls12")]
            Self::V1_2(ref mut connection) => connection.absorb(data),
            #[cfg(feature = "tls13")]
            Self::V1_3(ref mut connection) => connection.absorb(data),
            #[cfg(feature = "dtls")]
            Self::DTLS(ref mut connection) => connection.absorb(data),
        }
    }

    pub fn emit(&mut self, output: &mut Vec<u8>) -> Result<usize, TLSError> {
        match *self {
            #[cfg(feature = "tls10")]
            Self::V1_0(ref mut connection) => connection.emit(output),
            #[cfg(feature = "tls11")]
            Self::V1_1(ref mut connection) => connection.emit(output),
            #[cfg(feature = "tls12")]
            Self::V1_2(ref mut connection) => connection.emit(output),
            #[cfg(feature = "tls13")]
            Self::V1_3(ref mut connection) => connection.emit(output),
            #[cfg(feature = "dtls")]
            Self::DTLS(ref mut connection) => connection.emit(output),
        }
    }

    pub fn step(&mut self) -> Result<TLSHandshakeState, TLSError> {
        match *self {
            #[cfg(feature = "tls10")]
            Self::V1_0(ref mut connection) => connection.step(),
            #[cfg(feature = "tls11")]
            Self::V1_1(ref mut connection) => connection.step(),
            #[cfg(feature = "tls12")]
            Self::V1_2(ref mut connection) => connection.step(),
            #[cfg(feature = "tls13")]
            Self::V1_3(ref mut connection) => connection.step(),
            #[cfg(feature = "dtls")]
            Self::DTLS(ref mut connection) => connection.step(),
        }
    }

    pub async fn handshake(&mut self) -> Result<(), TLSError> {
        match *self {
            #[cfg(feature = "tls10")]
            Self::V1_0(ref mut connection) => connection.handshake().await,
            #[cfg(feature = "tls11")]
            Self::V1_1(ref mut connection) => connection.handshake().await,
            #[cfg(feature = "tls12")]
            Self::V1_2(ref mut connection) => connection.handshake().await,
            #[cfg(feature = "tls13")]
            Self::V1_3(ref mut connection) => connection.handshake().await,
            #[cfg(feature = "dtls")]
            Self::DTLS(ref mut connection) => connection.handshake().await,
        }
    }

    pub async fn send(&mut self, data: &[u8]) -> Result<usize, TLSError> {
        match *self {
            #[cfg(feature = "tls10")]
            Self::V1_0(ref mut connection) => connection.send(data).await,
            #[cfg(feature = "tls11")]
            Self::V1_1(ref mut connection) => connection.send(data).await,
            #[cfg(feature = "tls12")]
            Self::V1_2(ref mut connection) => connection.send(data).await,
            #[cfg(feature = "tls13")]
            Self::V1_3(ref mut connection) => connection.send(data).await,
            #[cfg(feature = "dtls")]
            Self::DTLS(ref mut connection) => connection.send(data).await,
        }
    }

    pub async fn receive(&mut self, data: &mut [u8]) -> Result<usize, TLSError> {
        match *self {
            #[cfg(feature = "tls10")]
            Self::V1_0(ref mut connection) => connection.receive(data).await,
            #[cfg(feature = "tls11")]
            Self::V1_1(ref mut connection) => connection.receive(data).await,
            #[cfg(feature = "tls12")]
            Self::V1_2(ref mut connection) => connection.receive(data).await,
            #[cfg(feature = "tls13")]
            Self::V1_3(ref mut connection) => connection.receive(data).await,
            #[cfg(feature = "dtls")]
            Self::DTLS(ref mut connection) => connection.receive(data).await,
        }
    }

    pub async fn refresh(&mut self) -> Result<(), TLSError> {
        match *self {
            #[cfg(feature = "tls10")]
            Self::V1_0(ref mut connection) => connection.refresh().await,
            #[cfg(feature = "tls11")]
            Self::V1_1(ref mut connection) => connection.refresh().await,
            #[cfg(feature = "tls12")]
            Self::V1_2(ref mut connection) => connection.refresh().await,
            #[cfg(feature = "tls13")]
            Self::V1_3(ref mut connection) => connection.refresh().await,
            #[cfg(feature = "dtls")]
            Self::DTLS(ref mut connection) => connection.refresh().await,
        }
    }

    pub async fn alert(&mut self, alert: TLSAlert) -> Result<(), TLSError> {
        match *self {
            #[cfg(feature = "tls10")]
            Self::V1_0(ref mut connection) => connection.alert(alert).await,
            #[cfg(feature = "tls11")]
            Self::V1_1(ref mut connection) => connection.alert(alert).await,
            #[cfg(feature = "tls12")]
            Self::V1_2(ref mut connection) => connection.alert(alert).await,
            #[cfg(feature = "tls13")]
            Self::V1_3(ref mut connection) => connection.alert(alert).await,
            #[cfg(feature = "dtls")]
            Self::DTLS(ref mut connection) => connection.alert(alert).await,
        }
    }

    pub async fn close(&mut self) -> Result<(), TLSError> {
        match *self {
            #[cfg(feature = "tls10")]
            Self::V1_0(ref mut connection) => connection.close().await,
            #[cfg(feature = "tls11")]
            Self::V1_1(ref mut connection) => connection.close().await,
            #[cfg(feature = "tls12")]
            Self::V1_2(ref mut connection) => connection.close().await,
            #[cfg(feature = "tls13")]
            Self::V1_3(ref mut connection) => connection.close().await,
            #[cfg(feature = "dtls")]
            Self::DTLS(ref mut connection) => connection.close().await,
        }
    }
}

use alloc::string::String;
use core::fmt;

use umineko_protocol_tls::TLSError;
use umineko_helpers::provider::ProviderError;
#[cfg(feature = "http30")]
use umineko_protocol_quic::QUICError;

#[derive(Debug, Clone, PartialEq)]
pub enum HTTPError {
    Version,
    StartLine(String),
    Header(String),
    Body(String),
    Compression(String),
    StreamState,
    Limit,
    Target(String),
    Upgrade(String),
    Redirect,
    TLS(TLSError),
    #[cfg(feature = "http30")]
    QUIC(QUICError),
    Transport,
    Provider(ProviderError),
    Closed,
    Timeout,
}

impl fmt::Display for HTTPError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl core::error::Error for HTTPError {}

impl From<TLSError> for HTTPError {
    fn from(error: TLSError) -> Self {
        Self::TLS(error)
    }
}

impl From<ProviderError> for HTTPError {
    fn from(error: ProviderError) -> Self {
        Self::Provider(error)
    }
}

#[cfg(feature = "http30")]
impl From<QUICError> for HTTPError {
    fn from(error: QUICError) -> Self {
        Self::QUIC(error)
    }
}

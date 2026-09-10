use alloc::string::String;
use core::fmt;

use umineko_protocol_tls::TLSError;
use umineko_helpers::provider::ProviderError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QUICTransportError {
    NoError,
    InternalError,
    ConnectionRefused,
    FlowControlError,
    StreamLimitError,
    StreamStateError,
    FinalSizeError,
    FrameEncodingError,
    TransportParameterError,
    ConnectionIDLimitError,
    ProtocolViolation,
    InvalidToken,
    ApplicationError,
    CryptoBufferExceeded,
    KeyUpdateError,
    AEADLimitReached,
    NoViablePath,
    Crypto(u8),
    Unknown(u64),
}

impl QUICTransportError {
    pub fn number(&self) -> u64 {
        todo!()
    }

    pub fn from_number(number: u64) -> Self {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QUICError {
    Version,
    Packet,
    Frame,
    Decryption,
    StreamState,
    FlowControl,
    Limit,
    Transport(QUICTransportError),
    Application(u64),
    TLS(TLSError),
    Path(String),
    Provider(ProviderError),
    Closed,
    Timeout,
}

impl fmt::Display for QUICError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl core::error::Error for QUICError {}

impl From<TLSError> for QUICError {
    fn from(error: TLSError) -> Self {
        Self::TLS(error)
    }
}

impl From<QUICTransportError> for QUICError {
    fn from(error: QUICTransportError) -> Self {
        Self::Transport(error)
    }
}

impl From<ProviderError> for QUICError {
    fn from(error: ProviderError) -> Self {
        Self::Provider(error)
    }
}

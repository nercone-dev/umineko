use alloc::string::String;
use core::fmt;

use umineko_helpers::provider::ProviderError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TLSAlert {
    CloseNotify,
    UnexpectedMessage,
    BadRecordMac,
    RecordOverflow,
    HandshakeFailure,
    BadCertificate,
    UnsupportedCertificate,
    CertificateRevoked,
    CertificateExpired,
    CertificateUnknown,
    IllegalParameter,
    UnknownCA,
    AccessDenied,
    DecodeError,
    DecryptError,
    ProtocolVersion,
    InsufficientSecurity,
    InternalError,
    InappropriateFallback,
    UserCanceled,
    MissingExtension,
    UnsupportedExtension,
    UnrecognizedName,
    BadCertificateStatusResponse,
    UnknownPSKIdentity,
    CertificateRequired,
    NoApplicationProtocol,
    Unknown(u8),
}

impl TLSAlert {
    pub fn number(&self) -> u8 {
        todo!()
    }

    pub fn from_number(number: u8) -> Self {
        todo!()
    }

    pub fn fatal(&self) -> bool {
        !matches!(self, Self::CloseNotify | Self::UserCanceled)
    }

    pub fn as_str(&self) -> &'static str {
        todo!()
    }
}

impl fmt::Display for TLSAlert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TLSError {
    Version,
    Cipher,
    Group,
    ApplicationProtocol,
    Record,
    Handshake,
    Extension(String),
    Certificate(String),
    Name(String),
    Decryption,
    State,
    Limit,
    Alert(TLSAlert),
    Closed,
    Transport,
    Provider(ProviderError),
    Timeout,
}

impl fmt::Display for TLSError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl core::error::Error for TLSError {}

impl From<TLSAlert> for TLSError {
    fn from(alert: TLSAlert) -> Self {
        Self::Alert(alert)
    }
}

impl From<ProviderError> for TLSError {
    fn from(error: ProviderError) -> Self {
        Self::Provider(error)
    }
}

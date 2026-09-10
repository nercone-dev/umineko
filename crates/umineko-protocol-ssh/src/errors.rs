use alloc::string::String;
use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SSHDisconnectReason {
    HostNotAllowedToConnect,
    ProtocolError,
    KeyExchangeFailed,
    MACError,
    CompressionError,
    ServiceNotAvailable,
    ProtocolVersionNotSupported,
    HostKeyNotVerifiable,
    ConnectionLost,
    ByApplication,
    TooManyConnections,
    AuthCancelledByUser,
    NoMoreAuthMethodsAvailable,
    IllegalUserName,
    Unknown(u32),
}

impl SSHDisconnectReason {
    pub fn number(&self) -> u32 {
        todo!()
    }

    pub fn from_number(number: u32) -> Self {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SSHError {
    Version(String),
    Packet,
    Negotiation(String),
    KeyExchange(String),
    HostKey(String),
    HostKeyChanged(String),
    Authentication,
    NoMoreMethods,
    Decryption,
    State,
    ChannelState,
    FlowControl,
    Limit,
    Disconnected(SSHDisconnectReason),
    Transport,
    Timeout,
}

impl fmt::Display for SSHError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl core::error::Error for SSHError {}

impl From<SSHDisconnectReason> for SSHError {
    fn from(reason: SSHDisconnectReason) -> Self {
        Self::Disconnected(reason)
    }
}

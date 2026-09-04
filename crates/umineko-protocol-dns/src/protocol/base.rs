use crate::errors::DNSError;
use crate::types::{DNSMessage, DNSLimits};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DNSTransport {
    UDP,
    TCP,
    QUIC,
    TLS,
    HTTPS,
}

impl DNSTransport {
    pub fn secure(&self) -> bool {
        matches!(self, Self::QUIC | Self::TLS | Self::HTTPS)
    }

    pub fn length_prefixed(&self) -> bool {
        matches!(self, Self::TCP | Self::TLS)
    }

    pub fn multiplexed(&self) -> bool {
        matches!(self, Self::QUIC | Self::HTTPS)
    }

    pub fn default_port(&self) -> u16 {
        match self {
            Self::UDP | Self::TCP => 53,
            Self::QUIC | Self::TLS => 853,
            Self::HTTPS => 443,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::UDP => "Do53/UDP",
            Self::TCP => "Do53/TCP",
            Self::QUIC => "DoQ",
            Self::TLS => "DoT",
            Self::HTTPS => "DoH",
        }
    }
}

///
#[derive(Debug)]
pub enum DNSConnection {
    #[cfg(feature = "udp")]
    UDP(crate::protocol::udp::DNSUDPConnection),
    #[cfg(feature = "tcp")]
    TCP(crate::protocol::tcp::DNSTCPConnection),
    #[cfg(feature = "quic")]
    QUIC(crate::protocol::quic::DNSQUICConnection),
    #[cfg(feature = "tls")]
    TLS(crate::protocol::tls::DNSTLSConnection),
    #[cfg(feature = "https")]
    HTTPS(crate::protocol::https::DNSHTTPSConnection),
}

impl DNSConnection {
    pub fn transport(&self) -> DNSTransport {
        todo!()
    }

    pub fn limits(&self) -> DNSLimits {
        todo!()
    }

    pub fn concurrency(&self) -> usize {
        todo!()
    }

    pub async fn send(&mut self, message: &DNSMessage) -> Result<(), DNSError> {
        todo!()
    }

    pub async fn receive(&mut self) -> Result<DNSMessage, DNSError> {
        todo!()
    }

    pub async fn query(&mut self, message: &DNSMessage) -> Result<DNSMessage, DNSError> {
        todo!()
    }

    pub async fn respond(&mut self, message: &DNSMessage) -> Result<(), DNSError> {
        todo!()
    }

    pub async fn close(&mut self) -> Result<(), DNSError> {
        todo!()
    }
}

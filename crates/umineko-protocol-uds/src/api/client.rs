use crate::errors::UDSError;
use crate::types::{UDSPath, UDSType, UDSLimits};
use crate::protocol::base::UDSConnection;
use crate::protocol::stream::UDSStreamConnection;
use crate::protocol::datagram::UDSDatagramConnection;
use crate::protocol::seqpacket::UDSSeqpacketConnection;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UDSClientConfig {
    pub kind: UDSType,
    pub receive_ancillary: bool,
    pub verify_credentials: bool,
}

impl Default for UDSClientConfig {
    fn default() -> Self {
        Self { kind: UDSType::Stream, receive_ancillary: true, verify_credentials: true }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct UDSClient {
    pub config: UDSClientConfig,
    pub limits: UDSLimits,
}

impl UDSClient {
    pub fn new(config: UDSClientConfig, limits: UDSLimits) -> Self {
        Self { config, limits }
    }

    pub async fn connect(&self, remote: UDSPath) -> Result<UDSConnection, UDSError> {
        match self.config.kind {
            UDSType::Stream => Ok(UDSConnection::Stream(UDSStreamConnection::connect_with(remote, &self.config, self.limits).await?)),
            UDSType::Datagram => Ok(UDSConnection::Datagram(UDSDatagramConnection::connect_with(remote, &self.config, self.limits).await?)),
            UDSType::Seqpacket => Ok(UDSConnection::Seqpacket(UDSSeqpacketConnection::connect_with(remote, &self.config, self.limits).await?)),
        }
    }
}


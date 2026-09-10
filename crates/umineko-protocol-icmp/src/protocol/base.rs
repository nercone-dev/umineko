use alloc::{sync::Arc, vec::Vec};
use crate::errors::ICMPError;
use crate::types::{ICMPVersion, ICMPType, ICMPCode};
use crate::provider::ICMPProvider;

use umineko_protocol_ip::IPAddress;
use umineko_helpers::provider::ProviderHandle;

pub trait ICMPPacket: Sized {
    fn version(&self) -> ICMPVersion;

    fn kind(&self) -> ICMPType;
    fn code(&self) -> ICMPCode;

    fn payload(&self) -> &[u8];

    fn encode(&self, source: IPAddress, destination: IPAddress) -> Result<Vec<u8>, ICMPError>;
    fn decode(data: &[u8], source: IPAddress, destination: IPAddress) -> Result<Self, ICMPError>;
}

///
#[derive(Debug)]
pub enum ICMPConnection {
    V4(crate::protocol::v4::ICMPv4Connection),
    V6(crate::protocol::v6::ICMPv6Connection),
}

impl ICMPConnection {
    pub fn from_provider(version: ICMPVersion, provider: Arc<dyn ICMPProvider>, handle: ProviderHandle) -> Result<Self, ICMPError> {
        match version {
            ICMPVersion::V4 => Ok(Self::V4(crate::protocol::v4::ICMPv4Connection::from_provider(provider, handle)?)),
            ICMPVersion::V6 => Ok(Self::V6(crate::protocol::v6::ICMPv6Connection::from_provider(provider, handle)?)),
        }
    }

    pub fn version(&self) -> ICMPVersion {
        todo!()
    }

    pub fn local(&self) -> IPAddress {
        todo!()
    }

    pub fn remote(&self) -> Option<IPAddress> {
        todo!()
    }

    pub async fn send(&mut self, destination: IPAddress, kind: ICMPType, code: ICMPCode, payload: &[u8]) -> Result<usize, ICMPError> {
        todo!()
    }

    pub async fn receive(&mut self, payload: &mut [u8]) -> Result<(ICMPType, ICMPCode, usize, IPAddress), ICMPError> {
        todo!()
    }

    pub async fn close(&mut self) -> Result<(), ICMPError> {
        todo!()
    }
}

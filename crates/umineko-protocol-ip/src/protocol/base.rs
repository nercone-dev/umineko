use alloc::{sync::Arc, vec::Vec};
use crate::errors::IPError;
use crate::types::{IPVersion, IPAddress, IPProtocol, IPToS};
use crate::provider::IPProvider;

use umineko_helpers::provider::ProviderHandle;

pub trait IPPacket: Sized {
    fn version(&self) -> IPVersion;

    fn source(&self) -> IPAddress;
    fn destination(&self) -> IPAddress;

    fn protocol(&self) -> IPProtocol;
    fn type_of_service(&self) -> IPToS;

    fn hop_limit(&self) -> u8;

    fn payload(&self) -> &[u8];

    fn encode(&self) -> Result<Vec<u8>, IPError>;
    fn decode(data: &[u8]) -> Result<Self, IPError>;
}

///
#[derive(Debug)]
pub enum IPConnection {
    #[cfg(feature = "ipv4")]
    V4(crate::protocol::v4::IPv4Connection),
    #[cfg(feature = "ipv6")]
    V6(crate::protocol::v6::IPv6Connection),
}

impl IPConnection {
    pub fn from_provider(version: IPVersion, provider: Arc<dyn IPProvider>, handle: ProviderHandle) -> Result<Self, IPError> {
        match version {
            #[cfg(feature = "ipv4")]
            IPVersion::V4 => Ok(Self::V4(crate::protocol::v4::IPv4Connection::from_provider(provider, handle)?)),
            #[cfg(feature = "ipv6")]
            IPVersion::V6 => Ok(Self::V6(crate::protocol::v6::IPv6Connection::from_provider(provider, handle)?)),
            #[allow(unreachable_patterns)]
            _ => {
                provider.release(handle);
                Err(IPError::Version)
            }
        }
    }

    pub fn version(&self) -> IPVersion {
        todo!()
    }

    pub fn local(&self) -> IPAddress {
        todo!()
    }

    pub fn remote(&self) -> Option<IPAddress> {
        todo!()
    }

    pub fn protocol(&self) -> IPProtocol {
        todo!()
    }

    pub fn mtu(&self) -> usize {
        todo!()
    }

    pub async fn send(&mut self, destination: IPAddress, payload: &[u8]) -> Result<usize, IPError> {
        todo!()
    }

    pub async fn receive(&mut self, payload: &mut [u8]) -> Result<(usize, IPAddress), IPError> {
        todo!()
    }

    pub async fn close(&mut self) -> Result<(), IPError> {
        todo!()
    }
}

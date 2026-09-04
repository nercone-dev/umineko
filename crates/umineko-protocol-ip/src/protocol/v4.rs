use alloc::{sync::Arc, vec::Vec};
use crate::errors::IPError;
use crate::types::{IPVersion, IPAddress, IPProtocol, IPToS};
use crate::protocol::base::IPPacket;
use crate::provider::IPProvider;

use umineko_helpers::provider::{ProviderBackend, ProviderHandle, ProviderInterest};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IPv4Option {
    pub kind: u8,
    pub data: Vec<u8>,
}

impl IPv4Option {
    pub fn encode(&self) -> Vec<u8> {
        todo!()
    }

    pub fn decode(data: &[u8]) -> Result<(Self, usize), IPError> {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IPv4Header {
    pub type_of_service: IPToS,
    pub identification: u16,
    pub dont_fragment: bool,
    pub more_fragments: bool,
    pub fragment_offset: u16,
    pub time_to_live: u8,
    pub protocol: IPProtocol,
    pub source: IPAddress,
    pub destination: IPAddress,
    pub options: Vec<IPv4Option>,
}

impl IPv4Header {
    pub const MINIMUM_SIZE: usize = 20;
    pub const MAXIMUM_SIZE: usize = 60;

    pub fn len(&self) -> usize {
        todo!()
    }

    pub fn encode(&self) -> Result<Vec<u8>, IPError> {
        todo!()
    }

    pub fn decode(data: &[u8]) -> Result<(Self, usize), IPError> {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IPv4Packet {
    pub header: IPv4Header,
    pub payload: Vec<u8>,
}

impl IPPacket for IPv4Packet {
    fn version(&self) -> IPVersion {
        IPVersion::V4
    }

    fn source(&self) -> IPAddress {
        self.header.source
    }

    fn destination(&self) -> IPAddress {
        self.header.destination
    }

    fn protocol(&self) -> IPProtocol {
        self.header.protocol
    }

    fn type_of_service(&self) -> IPToS {
        self.header.type_of_service
    }

    fn hop_limit(&self) -> u8 {
        self.header.time_to_live
    }

    fn payload(&self) -> &[u8] {
        &self.payload
    }

    fn encode(&self) -> Result<Vec<u8>, IPError> {
        todo!()
    }

    fn decode(data: &[u8]) -> Result<Self, IPError> {
        todo!()
    }
}

#[derive(Debug)]
pub struct IPv4Connection {
    local: IPAddress,
    remote: Option<IPAddress>,
    protocol: IPProtocol,
    mtu: usize,
    backend: ProviderBackend<dyn IPProvider>,
}

impl IPv4Connection {
    pub const VERSION: IPVersion = IPVersion::V4;

    pub fn from_provider(provider: Arc<dyn IPProvider>, handle: ProviderHandle) -> Result<Self, IPError> {
        let backend = ProviderBackend::Handle { provider: provider.clone(), handle };
        let local = provider.local(handle)?;
        let remote = provider.remote(handle)?;
        let protocol = provider.protocol(handle)?;
        let mtu = provider.mtu(handle)?;
        Ok(Self { local, remote, protocol, mtu, backend })
    }

    pub fn provider(&self) -> Option<&Arc<dyn IPProvider>> {
        self.backend.provider()
    }

    pub fn version(&self) -> IPVersion {
        Self::VERSION
    }

    pub fn local(&self) -> IPAddress {
        self.local
    }

    pub fn remote(&self) -> Option<IPAddress> {
        self.remote
    }

    pub fn protocol(&self) -> IPProtocol {
        self.protocol
    }

    pub fn mtu(&self) -> usize {
        self.mtu
    }

    pub async fn send(&mut self, destination: IPAddress, payload: &[u8]) -> Result<usize, IPError> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => Ok(ProviderInterest::Writable.retry(|cx| provider.poll_ready(*handle, ProviderInterest::Writable, cx), || provider.send(*handle, destination, payload)).await?),
        }
    }

    pub async fn receive(&mut self, payload: &mut [u8]) -> Result<(usize, IPAddress), IPError> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => Ok(ProviderInterest::Readable.retry(|cx| provider.poll_ready(*handle, ProviderInterest::Readable, cx), || provider.receive(*handle, payload)).await?),
        }
    }

    pub async fn close(&mut self) -> Result<(), IPError> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => Ok(provider.close(*handle)?),
        }
    }
}

use alloc::{sync::Arc, vec::Vec};
use crate::errors::IPError;
use crate::types::{IPVersion, IPAddress, IPProtocol, IPToS};
use crate::protocol::base::IPPacket;
use crate::provider::IPProvider;

use umineko_helpers::provider::{ProviderBackend, ProviderHandle, ProviderInterest};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IPv6ExtensionHeader {
    HopByHop(Vec<u8>),
    Routing(Vec<u8>),
    Fragment { identification: u32, offset: u16, more_fragments: bool },
    Destination(Vec<u8>),
    Authentication(Vec<u8>),
    Unknown { kind: u8, data: Vec<u8> },
}

impl IPv6ExtensionHeader {
    pub fn kind(&self) -> u8 {
        todo!()
    }

    pub fn encode(&self) -> Vec<u8> {
        todo!()
    }

    pub fn decode(kind: u8, data: &[u8]) -> Result<(Self, usize), IPError> {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IPv6Header {
    pub type_of_service: IPToS,
    pub flow_label: u32,
    pub next_header: IPProtocol,
    pub hop_limit: u8,
    pub source: IPAddress,
    pub destination: IPAddress,
}

impl IPv6Header {
    pub const SIZE: usize = 40;

    pub fn encode(&self, payload_length: usize) -> Result<Vec<u8>, IPError> {
        todo!()
    }

    pub fn decode(data: &[u8]) -> Result<(Self, usize), IPError> {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IPv6Packet {
    pub header: IPv6Header,
    pub extensions: Vec<IPv6ExtensionHeader>,
    pub payload: Vec<u8>,
}

impl IPv6Packet {
    pub fn upper_protocol(&self) -> IPProtocol {
        todo!()
    }
}

impl IPPacket for IPv6Packet {
    fn version(&self) -> IPVersion {
        IPVersion::V6
    }

    fn source(&self) -> IPAddress {
        self.header.source
    }

    fn destination(&self) -> IPAddress {
        self.header.destination
    }

    fn protocol(&self) -> IPProtocol {
        self.upper_protocol()
    }

    fn type_of_service(&self) -> IPToS {
        self.header.type_of_service
    }

    fn hop_limit(&self) -> u8 {
        self.header.hop_limit
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
pub struct IPv6Connection {
    local: IPAddress,
    remote: Option<IPAddress>,
    protocol: IPProtocol,
    mtu: usize,
    backend: ProviderBackend<dyn IPProvider>,
}

impl IPv6Connection {
    pub const VERSION: IPVersion = IPVersion::V6;

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

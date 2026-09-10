use alloc::{sync::Arc, vec::Vec};
use crate::errors::ICMPError;
use crate::types::{ICMPVersion, ICMPType, ICMPCode};
use crate::protocol::base::ICMPPacket;
use crate::provider::ICMPProvider;

use umineko_protocol_ip::IPAddress;
use umineko_helpers::provider::{ProviderBackend, ProviderHandle, ProviderInterest};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ICMPv6Packet {
    pub kind: ICMPType,
    pub code: ICMPCode,
    pub rest: [u8; 4],
    pub payload: Vec<u8>,
}

impl ICMPv6Packet {
    pub const HEADER_SIZE: usize = 8;
}

impl ICMPPacket for ICMPv6Packet {
    fn version(&self) -> ICMPVersion {
        ICMPVersion::V6
    }

    fn kind(&self) -> ICMPType {
        self.kind
    }

    fn code(&self) -> ICMPCode {
        self.code
    }

    fn payload(&self) -> &[u8] {
        &self.payload
    }

    fn encode(&self, source: IPAddress, destination: IPAddress) -> Result<Vec<u8>, ICMPError> {
        todo!()
    }

    fn decode(data: &[u8], source: IPAddress, destination: IPAddress) -> Result<Self, ICMPError> {
        todo!()
    }
}

#[derive(Debug)]
pub struct ICMPv6Connection {
    local: IPAddress,
    remote: Option<IPAddress>,
    backend: ProviderBackend<dyn ICMPProvider>,
}

impl ICMPv6Connection {
    pub const VERSION: ICMPVersion = ICMPVersion::V6;

    pub fn from_provider(provider: Arc<dyn ICMPProvider>, handle: ProviderHandle) -> Result<Self, ICMPError> {
        let backend = ProviderBackend::Handle { provider: provider.clone(), handle };
        let local = provider.local(handle)?;
        let remote = provider.remote(handle)?;
        Ok(Self { local, remote, backend })
    }

    pub fn provider(&self) -> Option<&Arc<dyn ICMPProvider>> {
        self.backend.provider()
    }

    pub fn version(&self) -> ICMPVersion {
        Self::VERSION
    }

    pub fn local(&self) -> IPAddress {
        self.local
    }

    pub fn remote(&self) -> Option<IPAddress> {
        self.remote
    }

    pub async fn send(&mut self, destination: IPAddress, kind: ICMPType, code: ICMPCode, payload: &[u8]) -> Result<usize, ICMPError> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => Ok(ProviderInterest::Writable.retry(|cx| provider.poll_ready(*handle, ProviderInterest::Writable, cx), || provider.send(*handle, destination, kind, code, payload)).await?),
        }
    }

    pub async fn receive(&mut self, payload: &mut [u8]) -> Result<(ICMPType, ICMPCode, usize, IPAddress), ICMPError> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => Ok(ProviderInterest::Readable.retry(|cx| provider.poll_ready(*handle, ProviderInterest::Readable, cx), || provider.receive(*handle, payload)).await?),
        }
    }

    pub async fn close(&mut self) -> Result<(), ICMPError> {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => Ok(provider.close(*handle)?),
        }
    }
}

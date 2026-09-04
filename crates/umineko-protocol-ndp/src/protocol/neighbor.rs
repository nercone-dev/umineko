use alloc::vec::Vec;
use crate::errors::NDPError;
use crate::types::{NDPType, NDPOption, LinkLayerAddress};
use crate::protocol::base::NDPMessage;

use umineko_protocol_ip::IPAddress;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeighborSolicitation {
    pub target: IPAddress,
    pub options: Vec<NDPOption>,
}

impl NeighborSolicitation {
    pub fn new(target: IPAddress, source: Option<LinkLayerAddress>) -> Self {
        todo!()
    }

    pub fn duplicate_detection(&self, source: IPAddress) -> bool {
        todo!()
    }

    pub fn advertise(&self, link_layer: LinkLayerAddress, router: bool, solicited: bool) -> NeighborAdvertisement {
        todo!()
    }
}

impl NDPMessage for NeighborSolicitation {
    fn kind(&self) -> NDPType {
        NDPType::NeighborSolicitation
    }

    fn options(&self) -> &[NDPOption] {
        &self.options
    }

    fn validate(&self, hop_limit: u8, source: IPAddress) -> Result<(), NDPError> {
        todo!()
    }

    fn encode(&self) -> Result<Vec<u8>, NDPError> {
        todo!()
    }

    fn decode(data: &[u8]) -> Result<Self, NDPError> {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeighborAdvertisement {
    pub target: IPAddress,
    pub router: bool,
    pub solicited: bool,
    pub override_cache: bool,
    pub options: Vec<NDPOption>,
}

impl NeighborAdvertisement {
    pub fn link_layer(&self) -> Option<&LinkLayerAddress> {
        todo!()
    }
}

impl NDPMessage for NeighborAdvertisement {
    fn kind(&self) -> NDPType {
        NDPType::NeighborAdvertisement
    }

    fn options(&self) -> &[NDPOption] {
        &self.options
    }

    fn validate(&self, hop_limit: u8, source: IPAddress) -> Result<(), NDPError> {
        todo!()
    }

    fn encode(&self) -> Result<Vec<u8>, NDPError> {
        todo!()
    }

    fn decode(data: &[u8]) -> Result<Self, NDPError> {
        todo!()
    }
}

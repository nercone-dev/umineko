use alloc::vec::Vec;
use crate::errors::NDPError;
use crate::types::{NDPType, NDPOption, LinkLayerAddress};
use crate::protocol::base::NDPMessage;

use umineko_protocol_ip::IPAddress;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterSolicitation {
    pub options: Vec<NDPOption>,
}

impl RouterSolicitation {
    pub fn new(source: Option<LinkLayerAddress>) -> Self {
        todo!()
    }
}

impl NDPMessage for RouterSolicitation {
    fn kind(&self) -> NDPType {
        NDPType::RouterSolicitation
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouterPrefix {
    pub prefix: IPAddress,
    pub length: u8,
    pub on_link: bool,
    pub autonomous: bool,
    pub valid_lifetime: u32,
    pub preferred_lifetime: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterAdvertisement {
    pub hop_limit: u8,
    pub managed: bool,
    pub other: bool,
    pub lifetime: u16,
    pub reachable_time: u32,
    pub retransmit_time: u32,
    pub options: Vec<NDPOption>,
}

impl RouterAdvertisement {
    pub fn prefixes(&self) -> Vec<RouterPrefix> {
        todo!()
    }

    pub fn mtu(&self) -> Option<u32> {
        todo!()
    }

    pub fn link_layer(&self) -> Option<&LinkLayerAddress> {
        todo!()
    }
}

impl NDPMessage for RouterAdvertisement {
    fn kind(&self) -> NDPType {
        NDPType::RouterAdvertisement
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

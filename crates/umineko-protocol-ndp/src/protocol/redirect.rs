use alloc::vec::Vec;
use crate::errors::NDPError;
use crate::types::{NDPType, NDPOption, LinkLayerAddress};
use crate::protocol::base::NDPMessage;

use umineko_protocol_ip::IPAddress;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redirect {
    pub target: IPAddress,
    pub destination: IPAddress,
    pub options: Vec<NDPOption>,
}

impl Redirect {
    pub fn link_layer(&self) -> Option<&LinkLayerAddress> {
        todo!()
    }

    pub fn quotation(&self) -> Option<&[u8]> {
        todo!()
    }

    pub fn trusted(&self, gateway: IPAddress) -> bool {
        todo!()
    }
}

impl NDPMessage for Redirect {
    fn kind(&self) -> NDPType {
        NDPType::Redirect
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

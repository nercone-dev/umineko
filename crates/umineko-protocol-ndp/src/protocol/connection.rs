use crate::errors::NDPError;
use crate::types::{LinkLayerAddress, NDPLimits};
use crate::protocol::router::RouterAdvertisement;

use umineko_protocol_ip::IPAddress;

#[derive(Debug)]
pub struct NDPConnection {
    local: IPAddress,
    link_layer: LinkLayerAddress,
    limits: NDPLimits,
}

impl NDPConnection {
    pub async fn open(local: IPAddress, link_layer: LinkLayerAddress, limits: NDPLimits) -> Result<Self, NDPError> {
        todo!()
    }

    pub fn local(&self) -> IPAddress {
        self.local
    }

    pub fn link_layer(&self) -> &LinkLayerAddress {
        &self.link_layer
    }

    pub fn limits(&self) -> NDPLimits {
        self.limits
    }

    pub async fn solicit_neighbor(&mut self, target: IPAddress) -> Result<(), NDPError> {
        todo!()
    }

    pub async fn advertise_neighbor(&mut self, target: IPAddress, solicited: bool) -> Result<(), NDPError> {
        todo!()
    }

    pub async fn solicit_router(&mut self) -> Result<(), NDPError> {
        todo!()
    }

    pub async fn advertise_router(&mut self, advertisement: &RouterAdvertisement) -> Result<(), NDPError> {
        todo!()
    }

    pub async fn redirect(&mut self, target: IPAddress, destination: IPAddress) -> Result<(), NDPError> {
        todo!()
    }

    pub async fn close(&mut self) -> Result<(), NDPError> {
        todo!()
    }
}

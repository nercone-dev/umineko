use crate::errors::ARPError;
use crate::types::{HardwareAddress, ARPLimits};
use crate::protocol::packet::ARPPacket;

use umineko_protocol_ip::IPAddress;

#[derive(Debug)]
pub struct ARPConnection {
    hardware: HardwareAddress,
    protocol: IPAddress,
    limits: ARPLimits,
}

impl ARPConnection {
    pub async fn open(hardware: HardwareAddress, protocol: IPAddress, limits: ARPLimits) -> Result<Self, ARPError> {
        todo!()
    }

    pub fn hardware(&self) -> &HardwareAddress {
        &self.hardware
    }

    pub fn protocol(&self) -> IPAddress {
        self.protocol
    }

    pub fn limits(&self) -> ARPLimits {
        self.limits
    }

    pub async fn send(&mut self, packet: &ARPPacket) -> Result<usize, ARPError> {
        todo!()
    }

    pub async fn receive(&mut self) -> Result<ARPPacket, ARPError> {
        todo!()
    }

    pub async fn request(&mut self, target: IPAddress) -> Result<(), ARPError> {
        todo!()
    }

    pub async fn reply(&mut self, request: &ARPPacket, hardware: HardwareAddress) -> Result<(), ARPError> {
        todo!()
    }

    pub async fn announce(&mut self) -> Result<(), ARPError> {
        todo!()
    }

    pub async fn close(&mut self) -> Result<(), ARPError> {
        todo!()
    }
}

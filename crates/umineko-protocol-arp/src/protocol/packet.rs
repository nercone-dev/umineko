use alloc::vec::Vec;
use crate::errors::ARPError;
use crate::types::{ARPOperation, ARPHardwareType, HardwareAddress};

use umineko_protocol_ip::IPAddress;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ARPPacket {
    pub hardware: ARPHardwareType,
    pub operation: ARPOperation,
    pub sender_hardware: HardwareAddress,
    pub sender_protocol: IPAddress,
    pub target_hardware: HardwareAddress,
    pub target_protocol: IPAddress,
}

impl ARPPacket {
    pub const MINIMUM_SIZE: usize = 28;

    pub fn request(sender_hardware: HardwareAddress, sender_protocol: IPAddress, target_protocol: IPAddress) -> Self {
        todo!()
    }

    pub fn reply(&self, hardware: HardwareAddress) -> Result<Self, ARPError> {
        todo!()
    }

    pub fn gratuitous(&self) -> bool {
        todo!()
    }

    pub fn encode(&self) -> Result<Vec<u8>, ARPError> {
        todo!()
    }

    pub fn decode(data: &[u8]) -> Result<Self, ARPError> {
        todo!()
    }
}

use alloc::vec::Vec;
use crate::errors::UDSError;
use crate::helpers::credentials::UDSCredentials;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UDSAncillary {
    descriptors: Vec<i32>,
    credentials: Option<UDSCredentials>,
}

impl UDSAncillary {
    pub fn new() -> Self {
        todo!()
    }

    pub fn push_descriptor(&mut self, descriptor: i32) -> Result<(), UDSError> {
        todo!()
    }

    pub fn descriptors(&self) -> &[i32] {
        todo!()
    }

    pub fn take_descriptors(&mut self) -> Vec<i32> {
        todo!()
    }

    pub fn set_credentials(&mut self, credentials: UDSCredentials) {
        todo!()
    }

    pub fn credentials(&self) -> Option<&UDSCredentials> {
        todo!()
    }

    pub fn is_empty(&self) -> bool {
        todo!()
    }

    pub fn encode(&self) -> Result<Vec<u8>, UDSError> {
        todo!()
    }

    pub fn decode(data: &[u8]) -> Result<Self, UDSError> {
        todo!()
    }
}

impl Default for UDSAncillary {
    fn default() -> Self {
        Self::new()
    }
}

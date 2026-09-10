use alloc::vec::Vec;
use crate::errors::IPError;
use crate::types::{IPVersion, IPAddress, IPLimits};

#[derive(Debug, Clone, PartialEq)]
pub struct IPFragmenter {
    version: IPVersion,
    mtu: usize,
    limits: IPLimits,
}

impl IPFragmenter {
    pub fn new(version: IPVersion, mtu: usize, limits: IPLimits) -> Self {
        todo!()
    }

    pub fn count(&self, length: usize) -> usize {
        todo!()
    }

    pub fn fragment(&self, identification: u32, payload: &[u8]) -> Result<Vec<Vec<u8>>, IPError> {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct IPReassembler {
    version: IPVersion,
    limits: IPLimits,
}

impl IPReassembler {
    pub fn new(version: IPVersion, limits: IPLimits) -> Self {
        todo!()
    }

    pub fn accept(&mut self, source: IPAddress, identification: u32, offset: u16, more_fragments: bool, payload: &[u8]) -> Result<Option<Vec<u8>>, IPError> {
        todo!()
    }

    pub fn expire(&mut self, elapsed: f64) -> usize {
        todo!()
    }

    pub fn clear(&mut self) {
        todo!()
    }
}

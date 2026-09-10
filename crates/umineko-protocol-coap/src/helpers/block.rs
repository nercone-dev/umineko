use alloc::vec::Vec;
use crate::errors::CoAPError;
use crate::types::CoAPLimits;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CoAPBlock {
    pub number: u32,
    pub more: bool,
    pub size: u16,
}

impl CoAPBlock {
    pub const MINIMUM_SIZE: u16 = 16;
    pub const MAXIMUM_SIZE: u16 = 1024;

    pub fn exponent(size: u16) -> Result<u8, CoAPError> {
        todo!()
    }

    pub fn offset(&self) -> u64 {
        todo!()
    }

    pub fn encode(&self) -> Result<u32, CoAPError> {
        todo!()
    }

    pub fn decode(value: u32) -> Result<Self, CoAPError> {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct CoAPBlockTransfer {
    buffer: Vec<u8>,
    size: u16,
    next: u32,
    limits: CoAPLimits,
}

impl CoAPBlockTransfer {
    pub fn new(size: u16, limits: CoAPLimits) -> Result<Self, CoAPError> {
        todo!()
    }

    pub fn next(&mut self, data: &[u8]) -> Option<(CoAPBlock, Vec<u8>)> {
        todo!()
    }

    pub fn accept(&mut self, block: CoAPBlock, data: &[u8]) -> Result<Option<Vec<u8>>, CoAPError> {
        todo!()
    }

    pub fn negotiate(&mut self, size: u16) -> Result<(), CoAPError> {
        todo!()
    }

    pub fn reset(&mut self) {
        todo!()
    }
}

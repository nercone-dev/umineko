use alloc::vec::Vec;
use crate::errors::HTTPError;
use crate::types::{HTTPHeaders, HTTPLimits};

#[derive(Debug, Clone, PartialEq)]
pub struct QPACK {
    capacity: usize,
    entries: Vec<(alloc::string::String, alloc::string::String)>,
}

impl QPACK {
    pub fn new(capacity: usize) -> Self {
        todo!()
    }

    pub fn encoder(&self) -> QPACKEncoder {
        todo!()
    }

    pub fn decoder(&self) -> QPACKDecoder {
        todo!()
    }

    pub fn lookup(index: usize) -> Option<(&'static str, &'static str)> {
        todo!()
    }

    pub fn insert(&mut self, name: &str, value: &str) {
        todo!()
    }

    pub fn absorb(&mut self, data: &[u8]) -> Result<(), HTTPError> {
        todo!()
    }

    pub fn len(&self) -> usize {
        todo!()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct QPACKEncoder {
    table: QPACK,
    limits: HTTPLimits,
}

impl QPACKEncoder {
    pub fn new(table: QPACK, limits: HTTPLimits) -> Self {
        todo!()
    }

    pub fn encode(&mut self, headers: &HTTPHeaders) -> Result<Vec<u8>, HTTPError> {
        todo!()
    }

    pub fn reset(&mut self) {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct QPACKDecoder {
    table: QPACK,
    limits: HTTPLimits,
}

impl QPACKDecoder {
    pub fn new(table: QPACK, limits: HTTPLimits) -> Self {
        todo!()
    }

    pub fn decode(&mut self, data: &[u8]) -> Result<HTTPHeaders, HTTPError> {
        todo!()
    }

    pub fn reset(&mut self) {
        todo!()
    }
}

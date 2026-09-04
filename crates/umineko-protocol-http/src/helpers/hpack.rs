use alloc::vec::Vec;
use crate::errors::HTTPError;
use crate::types::{HTTPHeaders, HTTPLimits};

#[derive(Debug, Clone, PartialEq)]
pub struct HPACK {
    capacity: usize,
    entries: Vec<(alloc::string::String, alloc::string::String)>,
}

impl HPACK {
    pub fn new(capacity: usize) -> Self {
        todo!()
    }

    pub fn encoder(&self) -> HPACKEncoder {
        todo!()
    }

    pub fn decoder(&self) -> HPACKDecoder {
        todo!()
    }

    pub fn lookup(index: usize) -> Option<(&'static str, &'static str)> {
        todo!()
    }

    pub fn insert(&mut self, name: &str, value: &str) {
        todo!()
    }

    pub fn resize(&mut self, capacity: usize) {
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
pub struct HPACKEncoder {
    table: HPACK,
    limits: HTTPLimits,
}

impl HPACKEncoder {
    pub fn new(table: HPACK, limits: HTTPLimits) -> Self {
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
pub struct HPACKDecoder {
    table: HPACK,
    limits: HTTPLimits,
}

impl HPACKDecoder {
    pub fn new(table: HPACK, limits: HTTPLimits) -> Self {
        todo!()
    }

    pub fn decode(&mut self, data: &[u8]) -> Result<HTTPHeaders, HTTPError> {
        todo!()
    }

    pub fn reset(&mut self) {
        todo!()
    }
}

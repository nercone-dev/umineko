use alloc::vec::Vec;
use crate::types::{LinkLayerAddress, NDPLimits};

use umineko_protocol_ip::IPAddress;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NDPEntryState {
    Incomplete,
    Reachable,
    Stale,
    Delay,
    Probe,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NDPEntry {
    pub address: IPAddress,
    pub link_layer: Option<LinkLayerAddress>,
    pub state: NDPEntryState,
    pub router: bool,
    pub elapsed: f64,
}

impl NDPEntry {
    pub fn usable(&self) -> bool {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct NDPCache {
    entries: Vec<NDPEntry>,
    limits: NDPLimits,
}

impl NDPCache {
    pub fn new(limits: NDPLimits) -> Self {
        todo!()
    }

    pub fn insert(&mut self, entry: NDPEntry) {
        todo!()
    }

    pub fn remove(&mut self, address: IPAddress) {
        todo!()
    }

    pub fn get(&self, address: IPAddress) -> Option<&NDPEntry> {
        todo!()
    }

    pub fn contains(&self, address: IPAddress) -> bool {
        todo!()
    }

    pub fn routers(&self) -> Vec<&NDPEntry> {
        todo!()
    }

    pub fn expire(&mut self, elapsed: f64) -> usize {
        todo!()
    }

    pub fn clear(&mut self) {
        todo!()
    }

    pub fn len(&self) -> usize {
        todo!()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

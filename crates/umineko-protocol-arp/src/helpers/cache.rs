use alloc::vec::Vec;
use crate::types::{HardwareAddress, ARPLimits};

use umineko_protocol_ip::IPAddress;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ARPEntryState {
    Incomplete,
    Reachable,
    Stale,
    Probe,
    Permanent,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ARPEntry {
    pub protocol: IPAddress,
    pub hardware: Option<HardwareAddress>,
    pub state: ARPEntryState,
    pub elapsed: f64,
}

impl ARPEntry {
    pub fn usable(&self) -> bool {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ARPCache {
    entries: Vec<ARPEntry>,
    limits: ARPLimits,
}

impl ARPCache {
    pub fn new(limits: ARPLimits) -> Self {
        todo!()
    }

    pub fn insert(&mut self, entry: ARPEntry) {
        todo!()
    }

    pub fn remove(&mut self, protocol: IPAddress) {
        todo!()
    }

    pub fn get(&self, protocol: IPAddress) -> Option<&ARPEntry> {
        todo!()
    }

    pub fn contains(&self, protocol: IPAddress) -> bool {
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

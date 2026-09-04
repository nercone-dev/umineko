use alloc::vec::Vec;
use crate::types::{IPVersion, IPAddress};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IPRoute {
    pub destination: IPAddress,
    pub prefix: u8,
    pub gateway: Option<IPAddress>,
    pub source: Option<IPAddress>,
    pub mtu: Option<usize>,
    pub metric: u32,
}

impl IPRoute {
    pub fn matches(&self, address: IPAddress) -> bool {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IPRoutingTable {
    routes: Vec<IPRoute>,
}

impl IPRoutingTable {
    pub fn new() -> Self {
        todo!()
    }

    pub fn insert(&mut self, route: IPRoute) {
        todo!()
    }

    pub fn remove(&mut self, destination: IPAddress, prefix: u8) {
        todo!()
    }

    pub fn lookup(&self, destination: IPAddress) -> Option<&IPRoute> {
        todo!()
    }

    pub fn routes(&self, version: IPVersion) -> Vec<&IPRoute> {
        todo!()
    }

    pub fn clear(&mut self) {
        todo!()
    }
}

impl Default for IPRoutingTable {
    fn default() -> Self {
        Self::new()
    }
}

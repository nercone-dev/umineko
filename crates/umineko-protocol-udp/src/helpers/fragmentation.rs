use crate::types::{UDPEndpoint, UDPLimits};

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct UDPPathDiscovery {
    remote: UDPEndpoint,
    mtu: usize,
    lower: usize,
    upper: usize,
    limits: UDPLimits,
}

impl UDPPathDiscovery {
    pub fn new(remote: UDPEndpoint, limits: UDPLimits) -> Self {
        todo!()
    }

    pub fn mtu(&self) -> usize {
        self.mtu
    }

    pub fn probe(&self) -> Option<usize> {
        todo!()
    }

    pub fn on_success(&mut self, size: usize) {
        todo!()
    }

    pub fn on_failure(&mut self, size: usize, reported: Option<usize>) {
        todo!()
    }

    pub fn reset(&mut self) {
        todo!()
    }
}

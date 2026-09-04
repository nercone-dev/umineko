use alloc::vec::Vec;
use crate::errors::DHCPError;
use crate::types::{DHCPClientID, DHCPLimits};

use umineko_protocol_ip::IPAddress;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DHCPLeaseState {
    Offered,
    Bound,
    Renewing,
    Rebinding,
    Expired,
    Declined,
}

impl DHCPLeaseState {
    pub fn usable(&self) -> bool {
        matches!(self, Self::Bound | Self::Renewing | Self::Rebinding)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct DHCPLease {
    pub client: DHCPClientID,
    pub address: IPAddress,
    pub state: DHCPLeaseState,
    pub lifetime: u32,
    pub elapsed: f64,
}

impl DHCPLease {
    pub fn should_renew(&self) -> bool {
        todo!()
    }

    pub fn should_rebind(&self) -> bool {
        todo!()
    }

    pub fn expired(&self) -> bool {
        todo!()
    }

    pub fn remaining(&self) -> u32 {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct DHCPPool {
    start: IPAddress,
    end: IPAddress,
    leases: Vec<DHCPLease>,
    limits: DHCPLimits,
}

impl DHCPPool {
    pub fn new(start: IPAddress, end: IPAddress, limits: DHCPLimits) -> Self {
        todo!()
    }

    pub fn allocate(&mut self, client: &DHCPClientID, requested: Option<IPAddress>) -> Result<IPAddress, DHCPError> {
        todo!()
    }

    pub fn commit(&mut self, client: &DHCPClientID, address: IPAddress, lifetime: u32) -> Result<(), DHCPError> {
        todo!()
    }

    pub fn release(&mut self, client: &DHCPClientID) {
        todo!()
    }

    pub fn decline(&mut self, address: IPAddress) {
        todo!()
    }

    pub fn get(&self, client: &DHCPClientID) -> Option<&DHCPLease> {
        todo!()
    }

    pub fn expire(&mut self, elapsed: f64) -> usize {
        todo!()
    }

    pub fn available(&self) -> usize {
        todo!()
    }
}

use alloc::vec::Vec;
use crate::errors::DHCPError;
use crate::types::{DHCPVersion, DHCPOption, DHCPClientID, DHCPLimits};
use crate::helpers::lease::DHCPLease;

use umineko_protocol_ip::IPAddress;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DHCPClientConfig {
    pub versions: Vec<DHCPVersion>,
    pub client_id: Option<DHCPClientID>,
    pub requested: Option<IPAddress>,
    pub parameters: Vec<u8>,

    pub duplicate_detection: bool,
    pub renew: bool,
}

impl Default for DHCPClientConfig {
    fn default() -> Self {
        Self {
            versions: [DHCPVersion::V6, DHCPVersion::V4].to_vec(),
            client_id: None,
            requested: None,
            parameters: Vec::new(),

            duplicate_detection: true,
            renew: true,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct DHCPClient {
    pub config: DHCPClientConfig,
    pub limits: DHCPLimits,
}

impl DHCPClient {
    pub fn new(config: DHCPClientConfig, limits: DHCPLimits) -> Self {
        todo!()
    }

    pub async fn acquire(&self) -> Result<(DHCPLease, Vec<DHCPOption>), DHCPError> {
        todo!()
    }

    pub async fn renew(&self, lease: &DHCPLease) -> Result<DHCPLease, DHCPError> {
        todo!()
    }

    pub async fn rebind(&self, lease: &DHCPLease) -> Result<DHCPLease, DHCPError> {
        todo!()
    }

    pub async fn release(&self, lease: &DHCPLease) -> Result<(), DHCPError> {
        todo!()
    }

    pub async fn inform(&self, address: IPAddress) -> Result<Vec<DHCPOption>, DHCPError> {
        todo!()
    }
}

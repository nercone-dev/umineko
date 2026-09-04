use alloc::vec::Vec;
use crate::errors::DHCPError;
use crate::types::{DHCPVersion, DHCPMessageType, DHCPOption, DHCPClientID, DHCPLimits};

use umineko_protocol_ip::IPAddress;

pub trait DHCPMessage: Sized {
    fn version(&self) -> DHCPVersion;

    fn kind(&self) -> DHCPMessageType;

    fn transaction(&self) -> u32;

    fn client_id(&self) -> Option<&DHCPClientID>;

    fn options(&self) -> &[DHCPOption];

    fn option(&self, kind: u16) -> Option<&DHCPOption>;

    fn assigned(&self) -> Option<IPAddress>;

    fn matches(&self, request: &Self) -> bool;

    fn encode(&self, limits: DHCPLimits) -> Result<Vec<u8>, DHCPError>;
    fn decode(data: &[u8], limits: DHCPLimits) -> Result<Self, DHCPError>;
}

///
#[derive(Debug)]
pub enum DHCPConnection {
    #[cfg(feature = "dhcpv4")]
    V4(crate::protocol::v4::DHCPv4Connection),
    #[cfg(feature = "dhcpv6")]
    V6(crate::protocol::v6::DHCPv6Connection),
}

impl DHCPConnection {
    pub fn version(&self) -> DHCPVersion {
        todo!()
    }

    pub fn limits(&self) -> DHCPLimits {
        todo!()
    }

    pub async fn offer(&mut self, client: &DHCPClientID, address: IPAddress, options: &[DHCPOption]) -> Result<(), DHCPError> {
        todo!()
    }

    pub async fn acknowledge(&mut self, client: &DHCPClientID, options: &[DHCPOption]) -> Result<(), DHCPError> {
        todo!()
    }

    pub async fn reject(&mut self, client: &DHCPClientID) -> Result<(), DHCPError> {
        todo!()
    }

    pub async fn close(&mut self) -> Result<(), DHCPError> {
        todo!()
    }
}

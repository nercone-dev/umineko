use alloc::vec::Vec;
use crate::errors::DHCPError;
use crate::types::{DHCPVersion, DHCPMessageType, DHCPOption, DHCPClientID, DHCPLimits};
use crate::protocol::base::DHCPMessage;

use umineko_protocol_ip::IPAddress;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DHCPv6Message {
    pub kind: DHCPMessageType,
    pub transaction: u32,
    pub client: Option<IPAddress>,
    pub assigned: Option<IPAddress>,
    pub server: Option<IPAddress>,
    pub relay: Option<IPAddress>,
    pub options: Vec<DHCPOption>,
}

impl DHCPMessage for DHCPv6Message {
    fn version(&self) -> DHCPVersion {
        DHCPVersion::V6
    }

    fn kind(&self) -> DHCPMessageType {
        self.kind
    }

    fn transaction(&self) -> u32 {
        self.transaction
    }

    fn client_id(&self) -> Option<&DHCPClientID> {
        todo!()
    }

    fn options(&self) -> &[DHCPOption] {
        &self.options
    }

    fn option(&self, kind: u16) -> Option<&DHCPOption> {
        todo!()
    }

    fn assigned(&self) -> Option<IPAddress> {
        self.assigned
    }

    fn matches(&self, request: &Self) -> bool {
        todo!()
    }

    fn encode(&self, limits: DHCPLimits) -> Result<Vec<u8>, DHCPError> {
        todo!()
    }

    fn decode(data: &[u8], limits: DHCPLimits) -> Result<Self, DHCPError> {
        todo!()
    }
}

#[derive(Debug)]
pub struct DHCPv6Connection {
    limits: DHCPLimits,
}

impl DHCPv6Connection {
    pub const VERSION: DHCPVersion = DHCPVersion::V6;

    pub async fn bind(limits: DHCPLimits) -> Result<Self, DHCPError> {
        todo!()
    }

    pub fn version(&self) -> DHCPVersion {
        Self::VERSION
    }

    pub fn limits(&self) -> DHCPLimits {
        self.limits
    }

    pub async fn send(&mut self, message: &DHCPv6Message) -> Result<(), DHCPError> {
        todo!()
    }

    pub async fn receive(&mut self) -> Result<DHCPv6Message, DHCPError> {
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

use crate::errors::NTPError;
use crate::types::{NTPVersion, NTPLimits};
use crate::protocol::base::NTPPacket;

#[derive(Debug)]
pub struct NTPV3Connection {
    limits: NTPLimits,
}

impl NTPV3Connection {
    pub const VERSION: NTPVersion = NTPVersion::V3;

    pub async fn connect(server: &str, port: u16, limits: NTPLimits) -> Result<Self, NTPError> {
        todo!()
    }

    pub fn version(&self) -> NTPVersion {
        Self::VERSION
    }

    pub fn limits(&self) -> NTPLimits {
        self.limits
    }

    pub async fn send(&mut self, packet: &NTPPacket) -> Result<(), NTPError> {
        todo!()
    }

    pub async fn receive(&mut self) -> Result<NTPPacket, NTPError> {
        todo!()
    }

    pub async fn query(&mut self, packet: &NTPPacket) -> Result<NTPPacket, NTPError> {
        todo!()
    }

    pub async fn reply(&mut self, packet: &NTPPacket) -> Result<(), NTPError> {
        todo!()
    }

    pub async fn close(&mut self) -> Result<(), NTPError> {
        todo!()
    }
}

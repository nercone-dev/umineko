use alloc::vec::Vec;
use crate::errors::NTPError;
use crate::types::{NTPVersion, NTPMode, NTPStratum, NTPTimestamp, NTPLeapIndicator, NTPLimits};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NTPPacket {
    pub leap: NTPLeapIndicator,
    pub version: NTPVersion,
    pub mode: NTPMode,
    pub stratum: NTPStratum,
    pub poll: i8,
    pub precision: i8,
    pub root_delay: u32,
    pub root_dispersion: u32,
    pub reference_id: [u8; 4],

    pub reference: NTPTimestamp,
    pub origin: NTPTimestamp,
    pub receive: NTPTimestamp,
    pub transmit: NTPTimestamp,
}

impl NTPPacket {
    pub const HEADER_SIZE: usize = 48;

    pub fn query(version: NTPVersion, transmit: NTPTimestamp) -> Self {
        todo!()
    }

    pub fn reply(&self, receive: NTPTimestamp, transmit: NTPTimestamp) -> Self {
        todo!()
    }

    pub fn matches(&self, query: &Self) -> bool {
        todo!()
    }

    pub fn validate(&self, limits: NTPLimits) -> Result<(), NTPError> {
        todo!()
    }

    pub fn encode(&self) -> Result<Vec<u8>, NTPError> {
        todo!()
    }

    pub fn decode(data: &[u8], limits: NTPLimits) -> Result<Self, NTPError> {
        todo!()
    }
}

///
#[derive(Debug)]
pub enum NTPConnection {
    V3(crate::protocol::v3::NTPV3Connection),
    V4(crate::protocol::v4::NTPV4Connection),
}

impl NTPConnection {
    pub fn version(&self) -> NTPVersion {
        todo!()
    }

    pub fn limits(&self) -> NTPLimits {
        todo!()
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

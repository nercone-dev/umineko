use alloc::vec::Vec;
use crate::errors::NTPError;
use crate::types::{NTPTimestamp, NTPLimits};
use crate::protocol::base::NTPPacket;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct NTPSample {
    pub offset: f64,
    pub delay: f64,
    pub dispersion: f64,
    pub elapsed: f64,
}

impl NTPSample {
    pub fn measure(origin: NTPTimestamp, receive: NTPTimestamp, transmit: NTPTimestamp, destination: NTPTimestamp) -> Self {
        todo!()
    }

    pub fn from_packet(packet: &NTPPacket, destination: NTPTimestamp) -> Self {
        todo!()
    }

    pub fn validate(&self, limits: NTPLimits) -> Result<(), NTPError> {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct NTPClock {
    samples: Vec<NTPSample>,
    offset: f64,
    frequency: f64,
    limits: NTPLimits,
}

impl NTPClock {
    pub fn new(limits: NTPLimits) -> Self {
        todo!()
    }

    pub fn offset(&self) -> f64 {
        self.offset
    }

    pub fn frequency(&self) -> f64 {
        self.frequency
    }

    pub fn insert(&mut self, sample: NTPSample) -> Result<(), NTPError> {
        todo!()
    }

    pub fn select(&self) -> Option<NTPSample> {
        todo!()
    }

    pub fn step_required(&self) -> bool {
        todo!()
    }

    pub fn poll_interval(&self) -> f64 {
        todo!()
    }

    pub fn reset(&mut self) {
        todo!()
    }
}

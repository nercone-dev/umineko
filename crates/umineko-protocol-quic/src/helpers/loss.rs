use alloc::vec::Vec;
use crate::protocol::packet::QUICPacketNumber;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QUICPacketNumberSpace {
    Initial,
    Handshake,
    ApplicationData,
}

#[derive(Debug, Clone, PartialEq)]
pub struct QUICLossDetection {
    largest_acknowledged: Option<QUICPacketNumber>,
    round_trip_time: f64,
    round_trip_variation: f64,
    minimum_round_trip_time: f64,
    probe_count: u8,
}

impl QUICLossDetection {
    pub const REORDERING_THRESHOLD: u64 = 3;

    pub fn new() -> Self {
        todo!()
    }

    pub fn round_trip_time(&self) -> f64 {
        self.round_trip_time
    }

    pub fn probe_timeout(&self) -> f64 {
        todo!()
    }

    pub fn loss_delay(&self) -> f64 {
        todo!()
    }

    pub fn on_sent(&mut self, space: QUICPacketNumberSpace, number: QUICPacketNumber, size: u64, ack_eliciting: bool) {
        todo!()
    }

    pub fn on_acknowledged(&mut self, space: QUICPacketNumberSpace, largest: QUICPacketNumber, delay: f64, elapsed: f64) -> Vec<QUICPacketNumber> {
        todo!()
    }

    pub fn on_timeout(&mut self, space: QUICPacketNumberSpace) -> Vec<QUICPacketNumber> {
        todo!()
    }

    pub fn discard(&mut self, space: QUICPacketNumberSpace) {
        todo!()
    }

    pub fn reset(&mut self) {
        todo!()
    }
}

impl Default for QUICLossDetection {
    fn default() -> Self {
        Self::new()
    }
}

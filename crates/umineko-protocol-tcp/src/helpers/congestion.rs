#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TCPCongestionState {
    SlowStart,
    CongestionAvoidance,
    FastRecovery,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TCPCongestion {
    state: TCPCongestionState,
    window: u32,
    threshold: u32,
    round_trip_time: f64,
    round_trip_variation: f64,
}

impl TCPCongestion {
    pub const INITIAL_WINDOW: u32 = 10;

    pub fn new(segment_size: u16) -> Self {
        todo!()
    }

    pub fn state(&self) -> TCPCongestionState {
        self.state
    }

    pub fn window(&self) -> u32 {
        self.window
    }

    pub fn retransmit_timeout(&self) -> f64 {
        todo!()
    }

    pub fn on_acknowledgement(&mut self, acknowledged: u32, round_trip_time: f64) {
        todo!()
    }

    pub fn on_loss(&mut self) {
        todo!()
    }

    pub fn on_congestion(&mut self) {
        todo!()
    }

    pub fn reset(&mut self) {
        todo!()
    }
}

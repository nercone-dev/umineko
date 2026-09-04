#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QUICCongestionState {
    SlowStart,
    CongestionAvoidance,
    Recovery,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct QUICCongestion {
    state: QUICCongestionState,
    window: u64,
    threshold: u64,
    in_flight: u64,
    max_datagram_size: u64,
}

impl QUICCongestion {
    pub const INITIAL_WINDOW: u64 = 10;
    pub const MINIMUM_WINDOW: u64 = 2;

    pub fn new(max_datagram_size: u64) -> Self {
        todo!()
    }

    pub fn state(&self) -> QUICCongestionState {
        self.state
    }

    pub fn window(&self) -> u64 {
        self.window
    }

    pub fn in_flight(&self) -> u64 {
        self.in_flight
    }

    pub fn sendable(&self, size: u64) -> bool {
        todo!()
    }

    pub fn on_sent(&mut self, size: u64) {
        todo!()
    }

    pub fn on_acknowledged(&mut self, size: u64, elapsed: f64) {
        todo!()
    }

    pub fn on_loss(&mut self, size: u64, persistent: bool) {
        todo!()
    }

    pub fn on_congestion(&mut self) {
        todo!()
    }

    pub fn reset(&mut self) {
        todo!()
    }
}

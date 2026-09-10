use crate::errors::QUICError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QUICFlowControl {
    send_limit: u64,
    sent: u64,
    receive_limit: u64,
    received: u64,
}

impl QUICFlowControl {
    pub fn new(send_limit: u64, receive_limit: u64) -> Self {
        todo!()
    }

    pub fn sendable(&self) -> u64 {
        todo!()
    }

    pub fn on_sent(&mut self, size: u64) -> Result<(), QUICError> {
        todo!()
    }

    pub fn on_received(&mut self, size: u64) -> Result<(), QUICError> {
        todo!()
    }

    pub fn set_send_limit(&mut self, limit: u64) {
        todo!()
    }

    pub fn consume(&mut self, size: u64) -> Option<u64> {
        todo!()
    }

    pub fn blocked(&self) -> bool {
        todo!()
    }
}

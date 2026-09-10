use crate::errors::CoAPError;
use crate::types::{CoAPCode, CoAPOption, CoAPLimits};
use crate::protocol::message::{CoAPMessage, CoAPToken};

#[derive(Debug)]
pub struct CoAPConnection {
    limits: CoAPLimits,
}

impl CoAPConnection {
    pub async fn open(remote: &str, port: u16, secure: bool, limits: CoAPLimits) -> Result<Self, CoAPError> {
        todo!()
    }

    pub fn limits(&self) -> CoAPLimits {
        self.limits
    }

    pub fn secure(&self) -> bool {
        todo!()
    }

    pub fn next_id(&mut self) -> u16 {
        todo!()
    }

    pub fn next_token(&mut self) -> CoAPToken {
        todo!()
    }

    pub async fn send(&mut self, message: &CoAPMessage) -> Result<(), CoAPError> {
        todo!()
    }

    pub async fn receive(&mut self) -> Result<CoAPMessage, CoAPError> {
        todo!()
    }

    pub async fn request(&mut self, message: &CoAPMessage) -> Result<CoAPMessage, CoAPError> {
        todo!()
    }

    pub async fn respond(&mut self, request: &CoAPMessage, code: CoAPCode, options: &[CoAPOption], payload: &[u8]) -> Result<(), CoAPError> {
        todo!()
    }

    pub async fn acknowledge(&mut self, request: &CoAPMessage) -> Result<(), CoAPError> {
        todo!()
    }

    pub async fn reset(&mut self, request: &CoAPMessage) -> Result<(), CoAPError> {
        todo!()
    }

    pub async fn notify(&mut self, token: &CoAPToken, code: CoAPCode, payload: &[u8]) -> Result<(), CoAPError> {
        todo!()
    }

    pub async fn retransmit(&mut self) -> Result<usize, CoAPError> {
        todo!()
    }

    pub async fn close(&mut self) -> Result<(), CoAPError> {
        todo!()
    }
}

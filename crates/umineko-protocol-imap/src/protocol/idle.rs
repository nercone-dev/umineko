use alloc::vec::Vec;
use crate::errors::IMAPError;
use crate::types::{IMAPResponse, IMAPLimits};

#[derive(Debug, Clone, PartialEq)]
pub struct IMAPIdle {
    active: bool,
    elapsed: f64,
    limits: IMAPLimits,
}

impl IMAPIdle {
    pub fn new(limits: IMAPLimits) -> Self {
        todo!()
    }

    pub fn active(&self) -> bool {
        self.active
    }

    pub async fn begin(&mut self) -> Result<(), IMAPError> {
        todo!()
    }

    pub async fn receive(&mut self) -> Result<Vec<IMAPResponse>, IMAPError> {
        todo!()
    }

    pub async fn end(&mut self) -> Result<(), IMAPError> {
        todo!()
    }

    pub fn should_refresh(&self) -> bool {
        todo!()
    }
}

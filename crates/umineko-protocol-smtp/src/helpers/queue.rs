use alloc::vec::Vec;
use crate::errors::SMTPError;
use crate::types::{SMTPAddress, SMTPLimits};

#[derive(Debug, Clone, PartialEq)]
pub struct SMTPQueueEntry {
    pub from: Option<SMTPAddress>,
    pub recipients: Vec<SMTPAddress>,
    pub data: Vec<u8>,
    pub attempts: u32,
    pub delay: f64,
    pub elapsed: f64,
}

impl SMTPQueueEntry {
    pub fn ready(&self) -> bool {
        todo!()
    }

    pub fn exhausted(&self, limits: SMTPLimits) -> bool {
        todo!()
    }

    pub fn backoff(&mut self) {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SMTPQueue {
    entries: Vec<SMTPQueueEntry>,
    limits: SMTPLimits,
}

impl SMTPQueue {
    pub fn new(limits: SMTPLimits) -> Self {
        todo!()
    }

    pub fn push(&mut self, entry: SMTPQueueEntry) -> Result<(), SMTPError> {
        todo!()
    }

    pub fn pop(&mut self) -> Option<SMTPQueueEntry> {
        todo!()
    }

    pub fn advance(&mut self, elapsed: f64) -> Vec<SMTPQueueEntry> {
        todo!()
    }

    pub fn clear(&mut self) {
        todo!()
    }

    pub fn len(&self) -> usize {
        todo!()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

use alloc::{string::String, vec::Vec};
use crate::errors::IMAPError;
use crate::types::{IMAPCapability, IMAPState, IMAPLimits};
use crate::helpers::mailbox::IMAPMailbox;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IMAPSession {
    state: IMAPState,
    capabilities: Vec<IMAPCapability>,
    mailbox: Option<IMAPMailbox>,
    username: Option<String>,
    secure: bool,
    tag_counter: u64,
}

impl IMAPSession {
    pub fn new() -> Self {
        todo!()
    }

    pub fn state(&self) -> IMAPState {
        self.state
    }

    pub fn mailbox(&self) -> Option<&IMAPMailbox> {
        self.mailbox.as_ref()
    }

    pub fn secure(&self) -> bool {
        self.secure
    }

    pub fn advance(&mut self, state: IMAPState) -> Result<(), IMAPError> {
        todo!()
    }

    pub fn select(&mut self, mailbox: IMAPMailbox) -> Result<(), IMAPError> {
        todo!()
    }

    pub fn unselect(&mut self) {
        todo!()
    }

    pub fn supports(&self, capability: &IMAPCapability) -> bool {
        todo!()
    }

    pub fn validate(&self, limits: IMAPLimits) -> Result<(), IMAPError> {
        todo!()
    }
}

impl Default for IMAPSession {
    fn default() -> Self {
        Self::new()
    }
}

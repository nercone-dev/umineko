use alloc::{string::String, vec::Vec};
use crate::errors::SMTPError;
use crate::types::{SMTPAddress, SMTPExtension, SMTPState, SMTPLimits};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SMTPTransaction {
    pub from: Option<SMTPAddress>,
    pub recipients: Vec<SMTPAddress>,
    pub data: Vec<u8>,
    pub declared_size: Option<u64>,
}

impl SMTPTransaction {
    pub fn new() -> Self {
        todo!()
    }

    pub fn ready(&self) -> bool {
        todo!()
    }

    pub fn reset(&mut self) {
        todo!()
    }
}

impl Default for SMTPTransaction {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SMTPSession {
    state: SMTPState,
    peer: Option<String>,
    extensions: Vec<SMTPExtension>,
    transaction: SMTPTransaction,
    secure: bool,
    authenticated: bool,
}

impl SMTPSession {
    pub fn new() -> Self {
        todo!()
    }

    pub fn state(&self) -> SMTPState {
        self.state
    }

    pub fn transaction(&self) -> &SMTPTransaction {
        &self.transaction
    }

    pub fn secure(&self) -> bool {
        self.secure
    }

    pub fn authenticated(&self) -> bool {
        self.authenticated
    }

    pub fn advance(&mut self, state: SMTPState) -> Result<(), SMTPError> {
        todo!()
    }

    pub fn reset(&mut self) {
        todo!()
    }

    pub fn validate(&self, limits: SMTPLimits) -> Result<(), SMTPError> {
        todo!()
    }
}

impl Default for SMTPSession {
    fn default() -> Self {
        Self::new()
    }
}

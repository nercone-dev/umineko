use alloc::{string::String, vec::Vec};
use crate::errors::FTPError;
use crate::types::{FTPDataType, FTPTransferMode, FTPState, FTPLimits};
use crate::protocol::data::FTPDataMode;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FTPSession {
    state: FTPState,
    username: Option<String>,
    directory: String,
    data_type: FTPDataType,
    transfer_mode: FTPTransferMode,
    data_mode: FTPDataMode,
    features: Vec<String>,
    secure: bool,
    data_secure: bool,
    rename_from: Option<String>,
    offset: u64,
}

impl FTPSession {
    pub fn new() -> Self {
        todo!()
    }

    pub fn state(&self) -> FTPState {
        self.state
    }

    pub fn directory(&self) -> &str {
        &self.directory
    }

    pub fn secure(&self) -> bool {
        self.secure
    }

    pub fn advance(&mut self, state: FTPState) -> Result<(), FTPError> {
        todo!()
    }

    pub fn change_directory(&mut self, path: &str) -> Result<(), FTPError> {
        todo!()
    }

    pub fn resolve(&self, path: &str) -> Result<String, FTPError> {
        todo!()
    }

    pub fn validate(&self, limits: FTPLimits) -> Result<(), FTPError> {
        todo!()
    }
}

impl Default for FTPSession {
    fn default() -> Self {
        Self::new()
    }
}

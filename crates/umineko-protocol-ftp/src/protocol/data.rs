use alloc::string::String;
use crate::errors::FTPError;
use crate::types::{FTPDataType, FTPTransferMode, FTPLimits};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FTPDataMode {
    Passive,
    Active,
}

impl FTPDataMode {
    pub fn extended(&self) -> bool {
        true
    }
}

#[derive(Debug)]
pub struct FTPDataConnection {
    mode: FTPDataMode,
    data_type: FTPDataType,
    transfer_mode: FTPTransferMode,
    secure: bool,
    offset: u64,
    limits: FTPLimits,
}

impl FTPDataConnection {
    pub fn mode(&self) -> FTPDataMode {
        self.mode
    }

    pub fn secure(&self) -> bool {
        self.secure
    }

    pub async fn connect(endpoint: &str, mode: FTPDataMode, limits: FTPLimits) -> Result<Self, FTPError> {
        todo!()
    }

    pub async fn listen(mode: FTPDataMode, limits: FTPLimits) -> Result<(Self, String), FTPError> {
        todo!()
    }

    pub async fn send(&mut self, data: &[u8]) -> Result<usize, FTPError> {
        todo!()
    }

    pub async fn receive(&mut self, data: &mut [u8]) -> Result<usize, FTPError> {
        todo!()
    }

    pub async fn finish(&mut self) -> Result<(), FTPError> {
        todo!()
    }

    pub async fn abort(&mut self) -> Result<(), FTPError> {
        todo!()
    }
}

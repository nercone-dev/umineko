use alloc::string::String;
use crate::errors::FTPError;
use crate::types::{FTPCommand, FTPReply, FTPReplyCode, FTPState, FTPLimits};
use crate::protocol::session::FTPSession;
use crate::protocol::data::FTPDataConnection;
use crate::helpers::listing::FTPEntry;

#[derive(Debug)]
pub struct FTPConnection {
    session: FTPSession,
    limits: FTPLimits,
}

impl FTPConnection {
    pub fn state(&self) -> FTPState {
        todo!()
    }

    pub fn session(&self) -> &FTPSession {
        &self.session
    }

    pub fn limits(&self) -> FTPLimits {
        self.limits
    }

    pub fn features(&self) -> &[String] {
        todo!()
    }

    pub fn secure(&self) -> bool {
        todo!()
    }

    pub fn data_secure(&self) -> bool {
        todo!()
    }

    pub async fn send(&mut self, command: FTPCommand) -> Result<(), FTPError> {
        todo!()
    }

    pub async fn receive(&mut self) -> Result<FTPReply, FTPError> {
        todo!()
    }

    pub async fn execute(&mut self, command: FTPCommand) -> Result<FTPReply, FTPError> {
        todo!()
    }

    pub async fn open_data(&mut self) -> Result<FTPDataConnection, FTPError> {
        todo!()
    }

    pub async fn reply(&mut self, reply: FTPReply) -> Result<(), FTPError> {
        todo!()
    }

    pub async fn reject(&mut self, code: FTPReplyCode, text: &str) -> Result<(), FTPError> {
        todo!()
    }

    pub async fn send_listing(&mut self, entries: &[FTPEntry]) -> Result<(), FTPError> {
        todo!()
    }

    pub async fn send_data(&mut self, data: &[u8]) -> Result<usize, FTPError> {
        todo!()
    }

    pub async fn receive_data(&mut self, data: &mut [u8]) -> Result<usize, FTPError> {
        todo!()
    }

    pub async fn secure_upgrade(&mut self) -> Result<(), FTPError> {
        todo!()
    }

    pub async fn close(&mut self) -> Result<(), FTPError> {
        todo!()
    }
}

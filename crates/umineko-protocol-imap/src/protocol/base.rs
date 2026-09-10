use crate::errors::IMAPError;
use crate::types::{IMAPTag, IMAPCommand, IMAPResponse, IMAPStatus, IMAPCapability, IMAPState, IMAPLimits};
use crate::protocol::session::IMAPSession;

#[derive(Debug)]
pub struct IMAPConnection {
    session: IMAPSession,
    limits: IMAPLimits,
}

impl IMAPConnection {
    pub fn state(&self) -> IMAPState {
        todo!()
    }

    pub fn session(&self) -> &IMAPSession {
        &self.session
    }

    pub fn limits(&self) -> IMAPLimits {
        self.limits
    }

    pub fn capabilities(&self) -> &[IMAPCapability] {
        todo!()
    }

    pub fn secure(&self) -> bool {
        todo!()
    }

    pub fn next_tag(&mut self) -> IMAPTag {
        todo!()
    }

    pub async fn send(&mut self, tag: &IMAPTag, command: IMAPCommand) -> Result<(), IMAPError> {
        todo!()
    }

    pub async fn receive(&mut self) -> Result<IMAPResponse, IMAPError> {
        todo!()
    }

    pub async fn execute(&mut self, command: IMAPCommand) -> Result<IMAPResponse, IMAPError> {
        todo!()
    }

    pub async fn reply(&mut self, response: IMAPResponse) -> Result<(), IMAPError> {
        todo!()
    }

    pub async fn reject(&mut self, status: IMAPStatus, text: &str) -> Result<(), IMAPError> {
        todo!()
    }

    pub async fn notify(&mut self, response: IMAPResponse) -> Result<(), IMAPError> {
        todo!()
    }

    pub async fn starttls(&mut self) -> Result<(), IMAPError> {
        todo!()
    }

    pub async fn close(&mut self) -> Result<(), IMAPError> {
        todo!()
    }
}

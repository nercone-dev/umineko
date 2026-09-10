use crate::errors::SMTPError;
use crate::types::{SMTPCommand, SMTPReply, SMTPReplyCode, SMTPExtension, SMTPState, SMTPLimits};
use crate::protocol::session::SMTPSession;

#[derive(Debug)]
pub struct SMTPConnection {
    session: SMTPSession,
    limits: SMTPLimits,
}

impl SMTPConnection {
    pub fn state(&self) -> SMTPState {
        todo!()
    }

    pub fn session(&self) -> &SMTPSession {
        &self.session
    }

    pub fn limits(&self) -> SMTPLimits {
        self.limits
    }

    pub fn extensions(&self) -> &[SMTPExtension] {
        todo!()
    }

    pub fn secure(&self) -> bool {
        todo!()
    }

    pub async fn send(&mut self, command: SMTPCommand) -> Result<(), SMTPError> {
        todo!()
    }

    pub async fn receive(&mut self) -> Result<SMTPReply, SMTPError> {
        todo!()
    }

    pub async fn execute(&mut self, command: SMTPCommand) -> Result<SMTPReply, SMTPError> {
        todo!()
    }

    pub async fn send_data(&mut self, data: &[u8]) -> Result<SMTPReply, SMTPError> {
        todo!()
    }

    pub async fn reply(&mut self, reply: SMTPReply) -> Result<(), SMTPError> {
        todo!()
    }

    pub async fn reject(&mut self, code: SMTPReplyCode, text: &str) -> Result<(), SMTPError> {
        todo!()
    }

    pub async fn starttls(&mut self) -> Result<(), SMTPError> {
        todo!()
    }

    pub async fn close(&mut self) -> Result<(), SMTPError> {
        todo!()
    }
}

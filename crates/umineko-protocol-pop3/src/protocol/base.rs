use crate::errors::POP3Error;
use crate::types::{POP3Command, POP3Response, POP3Capability, POP3State, POP3Limits};
use crate::protocol::session::POP3Session;

#[derive(Debug)]
pub struct POP3Connection {
    session: POP3Session,
    limits: POP3Limits,
}

impl POP3Connection {
    pub fn state(&self) -> POP3State {
        todo!()
    }

    pub fn session(&self) -> &POP3Session {
        &self.session
    }

    pub fn limits(&self) -> POP3Limits {
        self.limits
    }

    pub fn capabilities(&self) -> &[POP3Capability] {
        todo!()
    }

    pub fn secure(&self) -> bool {
        todo!()
    }

    pub async fn send(&mut self, command: POP3Command) -> Result<(), POP3Error> {
        todo!()
    }

    pub async fn receive(&mut self, multiline: bool) -> Result<POP3Response, POP3Error> {
        todo!()
    }

    pub async fn execute(&mut self, command: POP3Command) -> Result<POP3Response, POP3Error> {
        todo!()
    }

    pub async fn reply(&mut self, response: POP3Response) -> Result<(), POP3Error> {
        todo!()
    }

    pub async fn reject(&mut self, message: &str) -> Result<(), POP3Error> {
        todo!()
    }

    pub async fn starttls(&mut self) -> Result<(), POP3Error> {
        todo!()
    }

    pub async fn close(&mut self) -> Result<(), POP3Error> {
        todo!()
    }
}

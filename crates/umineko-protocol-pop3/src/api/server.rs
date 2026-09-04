use alloc::{string::String, vec::Vec};
use crate::errors::POP3Error;
use crate::types::{POP3Capability, POP3Limits};
use crate::protocol::base::POP3Connection;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct POP3ServerConfig {
    pub capabilities: Vec<POP3Capability>,
    pub hostname: String,

    pub apop: bool,
    pub starttls: bool,
    pub require_starttls: bool,
}

impl Default for POP3ServerConfig {
    fn default() -> Self {
        Self {
            capabilities: Vec::new(),
            hostname: String::new(),

            apop: true,
            starttls: true,
            require_starttls: true,
        }
    }
}

///
pub trait POP3Handler {
    async fn on_connection(&self, connection: &mut POP3Connection);
}

#[derive(Debug, Clone, Default)]
pub struct POP3Server {
    pub config: POP3ServerConfig,
    pub limits: POP3Limits,
}

impl POP3Server {
    pub fn new(config: POP3ServerConfig, limits: POP3Limits) -> Self {
        todo!()
    }

    pub async fn serve<H: POP3Handler>(&self, handler: H) -> Result<(), POP3Error> {
        todo!()
    }

    pub fn run<H: POP3Handler>(&self, handler: H, workers: usize) -> Result<(), POP3Error> {
        todo!()
    }
}

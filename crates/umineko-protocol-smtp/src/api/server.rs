use alloc::{string::String, vec::Vec};
use crate::errors::SMTPError;
use crate::types::SMTPLimits;
use crate::protocol::auth::SMTPAuth;
use crate::protocol::base::SMTPConnection;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SMTPServerConfig {
    pub hostname: String,
    pub mechanisms: Vec<SMTPAuth>,

    pub starttls: bool,
    pub require_starttls: bool,
    pub require_authentication: bool,
    pub relay: bool,
}

impl Default for SMTPServerConfig {
    fn default() -> Self {
        Self {
            hostname: String::new(),
            mechanisms: [SMTPAuth::SCRAMSHA256, SMTPAuth::Plain].to_vec(),

            starttls: true,
            require_starttls: true,
            require_authentication: true,
            relay: false,
        }
    }
}

///
pub trait SMTPHandler {
    async fn on_connection(&self, connection: &mut SMTPConnection);
}

#[derive(Debug, Clone, Default)]
pub struct SMTPServer {
    pub config: SMTPServerConfig,
    pub limits: SMTPLimits,
}

impl SMTPServer {
    pub fn new(config: SMTPServerConfig, limits: SMTPLimits) -> Self {
        todo!()
    }

    pub async fn serve<H: SMTPHandler>(&self, handler: H) -> Result<(), SMTPError> {
        todo!()
    }

    pub fn run<H: SMTPHandler>(&self, handler: H, workers: usize) -> Result<(), SMTPError> {
        todo!()
    }
}

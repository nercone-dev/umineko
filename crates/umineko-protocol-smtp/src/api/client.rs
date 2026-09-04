use alloc::{string::String, vec::Vec};
use crate::errors::SMTPError;
use crate::types::{SMTPAddress, SMTPLimits};
use crate::protocol::auth::{SMTPAuth, SMTPCredentials};
use crate::helpers::mime::MIMEMessage;
use crate::helpers::dsn::SMTPDeliveryStatus;
use crate::protocol::base::SMTPConnection;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SMTPClientConfig {
    pub hostname: String,
    pub mechanisms: Vec<SMTPAuth>,
    pub credentials: Option<SMTPCredentials>,

    pub starttls: bool,
    pub require_starttls: bool,
    pub pipelining: bool,
    pub delivery_status: bool,
}

impl Default for SMTPClientConfig {
    fn default() -> Self {
        Self {
            hostname: String::new(),
            mechanisms: [SMTPAuth::SCRAMSHA256, SMTPAuth::CRAMMD5, SMTPAuth::Plain].to_vec(),
            credentials: None,

            starttls: true,
            require_starttls: true,
            pipelining: true,
            delivery_status: false,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct SMTPClient {
    pub config: SMTPClientConfig,
    pub limits: SMTPLimits,
}

impl SMTPClient {
    pub fn new(config: SMTPClientConfig, limits: SMTPLimits) -> Self {
        todo!()
    }

    pub async fn connect(&self, host: &str, port: u16) -> Result<SMTPConnection, SMTPError> {
        todo!()
    }

    pub async fn send(&self, from: &SMTPAddress, recipients: &[SMTPAddress], message: &MIMEMessage) -> Result<Vec<SMTPDeliveryStatus>, SMTPError> {
        todo!()
    }

    pub async fn verify(&self, address: &SMTPAddress) -> Result<bool, SMTPError> {
        todo!()
    }
}


use alloc::vec::Vec;
use crate::errors::SOCKSError;
use crate::types::{SOCKSVersion, SOCKSCommand, SOCKSLimits};
use crate::helpers::authentication::SOCKSAuthentication;
use crate::protocol::base::SOCKSConnection;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SOCKSServerConfig {
    pub versions: Vec<SOCKSVersion>,
    pub methods: Vec<SOCKSAuthentication>,
    pub commands: Vec<SOCKSCommand>,

    pub resolve: bool,
}

impl Default for SOCKSServerConfig {
    fn default() -> Self {
        Self {
            versions: [SOCKSVersion::V5].to_vec(),
            methods: [SOCKSAuthentication::UsernamePassword].to_vec(),
            commands: [SOCKSCommand::Connect].to_vec(),

            resolve: true,
        }
    }
}

///
pub trait SOCKSHandler {
    async fn on_connection(&self, connection: &mut SOCKSConnection);
}

#[derive(Debug, Clone, Default)]
pub struct SOCKSServer {
    pub config: SOCKSServerConfig,
    pub limits: SOCKSLimits,
}

impl SOCKSServer {
    pub fn new(config: SOCKSServerConfig, limits: SOCKSLimits) -> Self {
        todo!()
    }

    pub async fn serve<H: SOCKSHandler>(&self, handler: H) -> Result<(), SOCKSError> {
        todo!()
    }

    pub fn run<H: SOCKSHandler>(&self, handler: H, workers: usize) -> Result<(), SOCKSError> {
        todo!()
    }
}

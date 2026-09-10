use alloc::{string::String, vec::Vec};
use crate::errors::QUICError;
use crate::types::{QUICVersion, QUICTransportParameters, QUICLimits};
use crate::protocol::base::QUICConnection;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QUICServerConfig {
    pub versions: Vec<QUICVersion>,
    pub parameters: QUICTransportParameters,

    pub application_protocols: Vec<String>,

    pub retry: bool,
    pub early_data: bool,
    pub migration: bool,
}

impl Default for QUICServerConfig {
    fn default() -> Self {
        Self {
            versions: [QUICVersion::V1, QUICVersion::V2].to_vec(),
            parameters: QUICTransportParameters::default(),

            application_protocols: Vec::new(),

            retry: false,
            early_data: false,
            migration: true,
        }
    }
}

///
pub trait QUICHandler {
    async fn on_connection(&self, connection: &mut QUICConnection);
}

#[derive(Debug, Clone)]
pub struct QUICServer {
    pub config: QUICServerConfig,
    pub limits: QUICLimits,
}

impl QUICServer {
    pub fn new(config: QUICServerConfig, limits: QUICLimits) -> Self {
        todo!()
    }

    pub async fn serve<H: QUICHandler>(&self, handler: H) -> Result<(), QUICError> {
        todo!()
    }

    pub fn run<H: QUICHandler>(&self, handler: H, workers: usize) -> Result<(), QUICError> {
        todo!()
    }
}

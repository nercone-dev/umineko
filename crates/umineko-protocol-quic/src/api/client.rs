use alloc::{string::String, vec::Vec};
use crate::errors::QUICError;
use crate::types::{QUICVersion, QUICTransportParameters, QUICLimits};
use crate::protocol::base::QUICConnection;
use crate::provider::{QUICProviderRequest, QUICProviders};
use umineko_helpers::provider::ProviderOpening;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QUICClientConfig {
    pub versions: Vec<QUICVersion>,
    pub parameters: QUICTransportParameters,

    pub application_protocols: Vec<String>,
    pub server_name: Option<String>,

    pub verify: bool,
    pub early_data: bool,
    pub migration: bool,
}

impl Default for QUICClientConfig {
    fn default() -> Self {
        Self {
            versions: [QUICVersion::V1, QUICVersion::V2].to_vec(),
            parameters: QUICTransportParameters::default(),

            application_protocols: Vec::new(),
            server_name: None,

            verify: true,
            early_data: false,
            migration: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct QUICClient {
    pub config: QUICClientConfig,
    pub limits: QUICLimits,
}

impl QUICClient {
    pub fn new(config: QUICClientConfig, limits: QUICLimits) -> Self {
        todo!()
    }

    pub async fn connect(&self, name: &str) -> Result<QUICConnection, QUICError> {
        match QUICProviders::open(&QUICProviderRequest::Client { name, config: &self.config, limits: &self.limits })? {
            Some(ProviderOpening { provider, handle }) => QUICConnection::from_provider(provider, handle, self.limits),
            None => todo!(),
        }
    }
}


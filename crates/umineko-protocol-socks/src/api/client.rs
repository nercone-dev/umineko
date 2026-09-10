use alloc::vec::Vec;
use crate::errors::SOCKSError;
use crate::types::{SOCKSVersion, SOCKSAddress, SOCKSLimits};
use crate::helpers::authentication::{SOCKSAuthentication, SOCKSCredentials};
use crate::protocol::base::SOCKSConnection;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SOCKSClientConfig {
    pub versions: Vec<SOCKSVersion>,
    pub methods: Vec<SOCKSAuthentication>,
    pub credentials: Option<SOCKSCredentials>,

    pub remote_resolution: bool,
}

impl Default for SOCKSClientConfig {
    fn default() -> Self {
        Self {
            versions: [SOCKSVersion::V5, SOCKSVersion::V4].to_vec(),
            methods: [SOCKSAuthentication::UsernamePassword, SOCKSAuthentication::None].to_vec(),
            credentials: None,

            remote_resolution: true,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct SOCKSClient {
    pub config: SOCKSClientConfig,
    pub limits: SOCKSLimits,
}

impl SOCKSClient {
    pub fn new(config: SOCKSClientConfig, limits: SOCKSLimits) -> Self {
        todo!()
    }

    pub async fn connect(&self, proxy: &str, address: SOCKSAddress, port: u16) -> Result<SOCKSConnection, SOCKSError> {
        todo!()
    }

    pub async fn bind(&self, proxy: &str, address: SOCKSAddress, port: u16) -> Result<SOCKSConnection, SOCKSError> {
        todo!()
    }

    pub async fn associate(&self, proxy: &str) -> Result<SOCKSConnection, SOCKSError> {
        todo!()
    }
}


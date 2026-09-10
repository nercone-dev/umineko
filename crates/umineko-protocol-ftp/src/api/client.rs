use alloc::{string::String, vec::Vec};
use crate::errors::FTPError;
use crate::types::{FTPDataType, FTPLimits};
use crate::protocol::data::FTPDataMode;
use crate::helpers::listing::{FTPEntry, FTPListing};
use crate::protocol::base::FTPConnection;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FTPClientConfig {
    pub username: Option<String>,
    pub password: Option<String>,

    pub data_mode: FTPDataMode,
    pub data_type: FTPDataType,
    pub listing: FTPListing,

    pub secure: bool,
    pub require_secure: bool,
    pub secure_data: bool,
}

impl Default for FTPClientConfig {
    fn default() -> Self {
        Self {
            username: None,
            password: None,

            data_mode: FTPDataMode::Passive,
            data_type: FTPDataType::Image,
            listing: FTPListing::Machine,

            secure: true,
            require_secure: true,
            secure_data: true,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct FTPClient {
    pub config: FTPClientConfig,
    pub limits: FTPLimits,
}

impl FTPClient {
    pub fn new(config: FTPClientConfig, limits: FTPLimits) -> Self {
        todo!()
    }

    pub async fn connect(&self, host: &str, port: u16) -> Result<FTPConnection, FTPError> {
        todo!()
    }

    pub async fn list(&self, path: Option<&str>) -> Result<Vec<FTPEntry>, FTPError> {
        todo!()
    }

    pub async fn retrieve(&self, path: &str, offset: u64) -> Result<Vec<u8>, FTPError> {
        todo!()
    }

    pub async fn store(&self, path: &str, data: &[u8], offset: u64) -> Result<(), FTPError> {
        todo!()
    }

    pub async fn delete(&self, path: &str) -> Result<(), FTPError> {
        todo!()
    }

    pub async fn rename(&self, from: &str, to: &str) -> Result<(), FTPError> {
        todo!()
    }

    pub async fn create_directory(&self, path: &str) -> Result<(), FTPError> {
        todo!()
    }

    pub async fn remove_directory(&self, path: &str) -> Result<(), FTPError> {
        todo!()
    }

    pub async fn size(&self, path: &str) -> Result<u64, FTPError> {
        todo!()
    }
}


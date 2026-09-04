use alloc::{string::String, vec::Vec};
use crate::errors::NTPError;
use crate::types::{NTPVersion, NTPTimestamp, NTPLimits};
use crate::helpers::clock::{NTPClock, NTPSample};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NTPClientConfig {
    pub versions: Vec<NTPVersion>,
    pub servers: Vec<String>,

    pub authenticate: bool,
    pub unique_identifier: bool,
    pub allow_step: bool,
}

impl Default for NTPClientConfig {
    fn default() -> Self {
        Self {
            versions: [NTPVersion::V4, NTPVersion::V3].to_vec(),
            servers: Vec::new(),

            authenticate: false,
            unique_identifier: true,
            allow_step: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct NTPClient {
    pub config: NTPClientConfig,
    pub limits: NTPLimits,
    pub clock: NTPClock,
}

impl NTPClient {
    pub fn new(config: NTPClientConfig, limits: NTPLimits) -> Self {
        todo!()
    }

    pub async fn query(&self, server: &str) -> Result<NTPSample, NTPError> {
        todo!()
    }

    pub async fn synchronize(&mut self) -> Result<f64, NTPError> {
        todo!()
    }

    pub fn now(&self, local: NTPTimestamp) -> NTPTimestamp {
        todo!()
    }
}

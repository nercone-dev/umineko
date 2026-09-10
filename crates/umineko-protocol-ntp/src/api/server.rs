use alloc::vec::Vec;
use crate::errors::NTPError;
use crate::types::{NTPVersion, NTPStratum, NTPLimits};
use crate::protocol::base::NTPConnection;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NTPServerConfig {
    pub versions: Vec<NTPVersion>,
    pub stratum: NTPStratum,
    pub reference_id: [u8; 4],

    pub authenticate: bool,
    pub reply_when_unsynchronized: bool,
}

impl Default for NTPServerConfig {
    fn default() -> Self {
        Self {
            versions: [NTPVersion::V4, NTPVersion::V3].to_vec(),
            stratum: NTPStratum::UNSYNCHRONIZED,
            reference_id: [0; 4],

            authenticate: false,
            reply_when_unsynchronized: false,
        }
    }
}

///
pub trait NTPHandler {
    async fn on_connection(&self, connection: &mut NTPConnection);
}

#[derive(Debug, Clone, Default)]
pub struct NTPServer {
    pub config: NTPServerConfig,
    pub limits: NTPLimits,
}

impl NTPServer {
    pub fn new(config: NTPServerConfig, limits: NTPLimits) -> Self {
        todo!()
    }

    pub async fn serve<H: NTPHandler>(&self, handler: H) -> Result<(), NTPError> {
        todo!()
    }

    pub fn run<H: NTPHandler>(&self, handler: H, workers: usize) -> Result<(), NTPError> {
        todo!()
    }
}

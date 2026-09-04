use alloc::{string::String, vec::Vec};
use crate::errors::MailError;
use crate::types::{MailResult, MailLimits};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BIMIIndicator {
    pub location: String,
    pub authority: Option<String>,
    pub data: Option<Vec<u8>>,
}

impl BIMIIndicator {
    pub fn secure(&self) -> bool {
        todo!()
    }

    pub fn validate(&self, limits: MailLimits) -> Result<(), MailError> {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BIMI {
    pub version: String,
    pub indicator: Option<BIMIIndicator>,
    pub selector: String,
}

impl BIMI {
    pub const VERSION: &'static str = "BIMI1";
    pub const DEFAULT_SELECTOR: &'static str = "default";

    pub fn parse(record: &str) -> Result<Self, MailError> {
        todo!()
    }

    pub fn encode(&self) -> String {
        todo!()
    }

    pub fn record_name(domain: &str, selector: &str) -> String {
        todo!()
    }

    pub fn evaluate(&self, dmarc: MailResult, limits: MailLimits) -> Result<MailResult, MailError> {
        todo!()
    }
}

use alloc::{string::String, vec::Vec};
use crate::errors::MailError;
use crate::types::{MailResult, MailIdentity, MailLimits};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DMARCPolicy {
    None,
    Quarantine,
    Reject,
}

impl DMARCPolicy {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Quarantine => "quarantine",
            Self::Reject => "reject",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        todo!()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DMARCAlignment {
    Strict,
    Relaxed,
}

impl DMARCAlignment {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Strict => "s",
            Self::Relaxed => "r",
        }
    }

    pub fn matches(&self, left: &str, right: &str) -> bool {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DMARC {
    pub version: String,
    pub policy: DMARCPolicy,
    pub subdomain_policy: Option<DMARCPolicy>,
    pub spf_alignment: DMARCAlignment,
    pub dkim_alignment: DMARCAlignment,
    pub percentage: u8,
    pub aggregate_reports: Vec<String>,
    pub forensic_reports: Vec<String>,
}

impl DMARC {
    pub const VERSION: &'static str = "DMARC1";
    pub const RECORD_PREFIX: &'static str = "_dmarc.";

    pub fn parse(record: &str) -> Result<Self, MailError> {
        todo!()
    }

    pub fn encode(&self) -> String {
        todo!()
    }

    pub fn record_name(domain: &str) -> String {
        todo!()
    }

    pub fn evaluate(&self, identity: &MailIdentity, spf: MailResult, spf_domain: Option<&str>, dkim: MailResult, dkim_domain: Option<&str>, limits: MailLimits) -> Result<(MailResult, DMARCPolicy), MailError> {
        todo!()
    }
}

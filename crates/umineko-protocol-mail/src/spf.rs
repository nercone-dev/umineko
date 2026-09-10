use alloc::{string::String, vec::Vec};
use crate::errors::MailError;
use crate::types::{MailResult, MailIdentity, MailLimits};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SPFQualifier {
    Pass,
    Fail,
    SoftFail,
    Neutral,
}

impl SPFQualifier {
    pub fn symbol(&self) -> char {
        match self {
            Self::Pass => '+',
            Self::Fail => '-',
            Self::SoftFail => '~',
            Self::Neutral => '?',
        }
    }

    pub fn from_symbol(symbol: char) -> Option<Self> {
        todo!()
    }

    pub fn result(&self) -> MailResult {
        match self {
            Self::Pass => MailResult::Pass,
            Self::Fail => MailResult::Fail,
            Self::SoftFail => MailResult::SoftFail,
            Self::Neutral => MailResult::Neutral,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SPFMechanism {
    All,
    A { domain: Option<String>, prefix4: Option<u8>, prefix6: Option<u8> },
    MX { domain: Option<String>, prefix4: Option<u8>, prefix6: Option<u8> },
    PTR(Option<String>),
    IPv4 { address: [u8; 4], prefix: u8 },
    IPv6 { address: [u8; 16], prefix: u8 },
    Include(String),
    Exists(String),
}

impl SPFMechanism {
    pub fn requires_lookup(&self) -> bool {
        !matches!(self, Self::All | Self::IPv4 { .. } | Self::IPv6 { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SPF {
    pub version: String,
    pub mechanisms: Vec<(SPFQualifier, SPFMechanism)>,
    pub redirect: Option<String>,
    pub explanation: Option<String>,
}

impl SPF {
    pub const VERSION: &'static str = "v=spf1";
    pub const RECORD_PREFIX: &'static str = "v=spf1 ";

    pub fn parse(record: &str) -> Result<Self, MailError> {
        todo!()
    }

    pub fn encode(&self) -> String {
        todo!()
    }

    pub fn evaluate(&self, identity: &MailIdentity, limits: MailLimits) -> Result<MailResult, MailError> {
        todo!()
    }

    pub fn expand(&self, macro_text: &str, identity: &MailIdentity) -> Result<String, MailError> {
        todo!()
    }
}

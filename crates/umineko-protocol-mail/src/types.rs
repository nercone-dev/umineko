use alloc::string::String;
use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MailResult {
    Pass,
    Fail,
    SoftFail,
    Neutral,
    None,
    TempError,
    PermError,
}

impl MailResult {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::SoftFail => "softfail",
            Self::Neutral => "neutral",
            Self::None => "none",
            Self::TempError => "temperror",
            Self::PermError => "permerror",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        todo!()
    }

    pub fn acceptable(&self) -> bool {
        matches!(self, Self::Pass | Self::Neutral | Self::None)
    }

    pub fn transient(&self) -> bool {
        matches!(self, Self::TempError)
    }
}

impl fmt::Display for MailResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailIdentity {
    pub envelope_from: Option<String>,
    pub header_from: Option<String>,
    pub helo: Option<String>,
    pub address: Option<String>,
}

impl MailIdentity {
    pub fn domain(&self) -> Option<&str> {
        todo!()
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MailLimits {
    pub max_lookup_count: u8,
    pub max_expansion_count: u8,
    pub max_record_size: u32,
    pub max_signature_count: u8,
    pub max_signed_header_count: u16,
    pub max_body_size: u64,

    pub lookup_timeout: f64,
    pub max_signature_lifetime: f64,
}

impl Default for MailLimits {
    fn default() -> Self {
        Self {
            max_lookup_count: 10,
            max_expansion_count: 10,
            max_record_size: 4 * 1024,
            max_signature_count: 8,
            max_signed_header_count: 128,
            max_body_size: 32 * 1024 * 1024,

            lookup_timeout: 20.0,
            max_signature_lifetime: 30.0 * 86400.0,
        }
    }
}

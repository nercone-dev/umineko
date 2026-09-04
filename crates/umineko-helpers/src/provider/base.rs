use alloc::{string::String, vec::Vec};
use core::fmt;
use core::future::poll_fn;
use core::task::{Context, Poll};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProviderCategory {
    IP,
    ICMP,
    UDS,
    TCP,
    UDP,
    TLS,
    QUIC,
    HTTP,
    DNS,
    Hash,
    Cipher,
    Signature,
    Exchange,
    KDF,
    Codec,
}

impl ProviderCategory {
    pub const ALL: [Self; 15] = [Self::IP, Self::ICMP, Self::UDS, Self::TCP, Self::UDP, Self::TLS, Self::QUIC, Self::HTTP, Self::DNS, Self::Hash, Self::Cipher, Self::Signature, Self::Exchange, Self::KDF, Self::Codec];

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::IP => "ip",
            Self::ICMP => "icmp",
            Self::UDS => "uds",
            Self::TCP => "tcp",
            Self::UDP => "udp",
            Self::TLS => "tls",
            Self::QUIC => "quic",
            Self::HTTP => "http",
            Self::DNS => "dns",
            Self::Hash => "hash",
            Self::Cipher => "cipher",
            Self::Signature => "signature",
            Self::Exchange => "exchange",
            Self::KDF => "kdf",
            Self::Codec => "codec",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|category| category.as_str() == name)
    }
}

impl fmt::Display for ProviderCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProviderHandle {
    pub category: ProviderCategory,
    pub value: u64,
}

impl ProviderHandle {
    pub fn new(category: ProviderCategory, value: u64) -> Self {
        Self { category, value }
    }
}

impl fmt::Display for ProviderHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}#{}", self.category, self.value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderError {
    Unsupported,
    Unavailable,
    WouldBlock,
    Permission,
    Argument,
    Exhausted,
    Interrupted,
    Timeout,
    Closed,
    Authentication,
    Verification,
    Format,
    Truncated,
    Limit,
    System(i32),
}

impl ProviderError {
    pub fn declined(&self) -> bool {
        matches!(self, Self::Unsupported | Self::Unavailable)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Unsupported => "unsupported",
            Self::Unavailable => "unavailable",
            Self::WouldBlock => "would block",
            Self::Permission => "permission denied",
            Self::Argument => "invalid argument",
            Self::Exhausted => "resource exhausted",
            Self::Interrupted => "interrupted",
            Self::Timeout => "timeout",
            Self::Closed => "closed",
            Self::Authentication => "authentication failed",
            Self::Verification => "verification failed",
            Self::Format => "invalid format",
            Self::Truncated => "truncated",
            Self::Limit => "limit exceeded",
            Self::System(_) => "system error",
        }
    }
}

impl fmt::Display for ProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::System(code) => write!(f, "system error {code}"),
            other => f.write_str(other.as_str()),
        }
    }
}

impl core::error::Error for ProviderError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProviderInterest {
    Readable,
    Writable,
    Both,
}

impl ProviderInterest {
    pub fn readable(&self) -> bool {
        matches!(self, Self::Readable | Self::Both)
    }

    pub fn writable(&self) -> bool {
        matches!(self, Self::Writable | Self::Both)
    }

    pub async fn retry<T>(self, mut poll: impl FnMut(&mut Context<'_>) -> Poll<Result<(), ProviderError>>, mut operation: impl FnMut() -> Result<T, ProviderError>) -> Result<T, ProviderError> {
        loop {
            match operation() {
                Err(ProviderError::WouldBlock) => poll_fn(|cx| poll(cx)).await?,
                Err(ProviderError::Interrupted) => {}
                result => return result,
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderOrder {
    Priority,
    Explicit(Vec<String>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProviderFallback {
    Never,
    Declined,
    Any,
}

impl ProviderFallback {
    pub fn continues(&self, error: &ProviderError) -> bool {
        match self {
            Self::Never => false,
            Self::Declined => error.declined(),
            Self::Any => true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderPolicy {
    pub order: ProviderOrder,
    pub fallback: ProviderFallback,
}

impl ProviderPolicy {
    pub const BUILTIN: &'static str = "umineko";
    pub const DEFAULT: Self = Self { order: ProviderOrder::Priority, fallback: ProviderFallback::Declined };

    pub fn builtin() -> Self {
        Self::only(Self::BUILTIN)
    }

    pub fn only(name: &str) -> Self {
        Self { order: ProviderOrder::Explicit([String::from(name)].to_vec()), fallback: ProviderFallback::Never }
    }

    pub fn explicit(names: &[&str]) -> Self {
        Self { order: ProviderOrder::Explicit(names.iter().map(|name| String::from(*name)).collect()), fallback: ProviderFallback::Declined }
    }
}

impl Default for ProviderPolicy {
    fn default() -> Self {
        Self::DEFAULT
    }
}

pub trait Provider: Send + Sync {
    fn name(&self) -> &'static str;

    fn priority(&self) -> i32 {
        0
    }

    fn release(&self, handle: ProviderHandle);
}

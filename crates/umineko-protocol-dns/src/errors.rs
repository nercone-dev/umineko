use alloc::string::String;
use core::fmt;
use crate::types::DNSResponseCode;

use umineko_helpers::provider::ProviderError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DNSError {
    Name(String),
    Syntax,
    Compression,
    Truncated,
    Limit,
    Response(DNSResponseCode),
    Mismatch,
    Validation(String),
    Alias,
    Transport,
    Provider(ProviderError),
    Timeout,
}

impl fmt::Display for DNSError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl core::error::Error for DNSError {}

impl From<DNSResponseCode> for DNSError {
    fn from(code: DNSResponseCode) -> Self {
        Self::Response(code)
    }
}

impl From<ProviderError> for DNSError {
    fn from(error: ProviderError) -> Self {
        Self::Provider(error)
    }
}

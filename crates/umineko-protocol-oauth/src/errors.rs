use alloc::string::String;
use core::fmt;

use umineko_protocol_http::HTTPError;
use umineko_url::URLError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OAuthErrorCode {
    InvalidRequest,
    InvalidClient,
    InvalidGrant,
    UnauthorizedClient,
    UnsupportedGrantType,
    InvalidScope,
    AccessDenied,
    UnsupportedResponseType,
    ServerError,
    TemporarilyUnavailable,
    AuthorizationPending,
    SlowDown,
    ExpiredToken,
    Unknown,
}

impl OAuthErrorCode {
    pub fn as_str(&self) -> &'static str {
        todo!()
    }

    pub fn from_name(name: &str) -> Self {
        todo!()
    }

    pub fn retryable(&self) -> bool {
        matches!(self, Self::TemporarilyUnavailable | Self::AuthorizationPending | Self::SlowDown)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum OAuthError {
    Syntax(String),
    Response { code: OAuthErrorCode, description: Option<String> },
    State,
    Verifier,
    Expired,
    Scope(String),
    RedirectURI(String),
    Discovery(String),
    URL(URLError),
    HTTP(HTTPError),
    Timeout,
}

impl fmt::Display for OAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl core::error::Error for OAuthError {}

impl From<URLError> for OAuthError {
    fn from(error: URLError) -> Self {
        Self::URL(error)
    }
}

impl From<HTTPError> for OAuthError {
    fn from(error: HTTPError) -> Self {
        Self::HTTP(error)
    }
}

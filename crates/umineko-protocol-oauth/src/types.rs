use alloc::{string::String, vec::Vec};
use core::fmt;
use crate::errors::OAuthError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OAuthGrant {
    AuthorizationCode { code: String, redirect_uri: String, verifier: Option<String> },
    RefreshToken(String),
    ClientCredentials,
    DeviceCode(String),
    TokenExchange { subject: String, subject_type: String },
    Unknown(String),
}

impl OAuthGrant {
    pub fn as_str(&self) -> &str {
        todo!()
    }

    pub fn interactive(&self) -> bool {
        matches!(self, Self::AuthorizationCode { .. } | Self::DeviceCode(_))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OAuthTokenType {
    Bearer,
    DPoP,
    MutualTLS,
}

impl OAuthTokenType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Bearer => "Bearer",
            Self::DPoP => "DPoP",
            Self::MutualTLS => "mutual-TLS",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        todo!()
    }

    pub fn bearer(&self) -> bool {
        matches!(self, Self::Bearer)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct OAuthToken {
    pub access_token: String,
    pub token_type: OAuthTokenType,
    pub expires_in: Option<u64>,
    pub refresh_token: Option<String>,
    pub scope: Option<OAuthScope>,
    pub id_token: Option<String>,
    pub elapsed: f64,
}

impl OAuthToken {
    pub fn parse(body: &[u8]) -> Result<Self, OAuthError> {
        todo!()
    }

    pub fn expired(&self, leeway: u64) -> bool {
        todo!()
    }

    pub fn should_refresh(&self) -> bool {
        todo!()
    }

    pub fn authorization(&self) -> String {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthScope(Vec<String>);

impl OAuthScope {
    pub const SEPARATOR: char = ' ';

    pub fn new() -> Self {
        todo!()
    }

    pub fn parse(text: &str) -> Result<Self, OAuthError> {
        todo!()
    }

    pub fn push(&mut self, scope: &str) {
        todo!()
    }

    pub fn contains(&self, scope: &str) -> bool {
        todo!()
    }

    pub fn covers(&self, requested: &Self) -> bool {
        todo!()
    }

    pub fn as_slice(&self) -> &[String] {
        todo!()
    }
}

impl Default for OAuthScope {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for OAuthScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OAuthClientType {
    Confidential,
    Public,
}

impl OAuthClientType {
    pub fn requires_verifier(&self) -> bool {
        matches!(self, Self::Public)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct OAuthLimits {
    pub max_response_size: u32,
    pub max_scope_count: u16,
    pub max_redirect_uri_count: u8,
    pub max_state_length: u16,

    pub code_lifetime: u64,
    pub token_lifetime: u64,
    pub refresh_lifetime: u64,
    pub leeway: u64,

    pub poll_interval: f64,
    pub request_timeout: f64,
    pub discovery_timeout: f64,
}

impl Default for OAuthLimits {
    fn default() -> Self {
        Self {
            max_response_size: 256 * 1024,
            max_scope_count: 64,
            max_redirect_uri_count: 16,
            max_state_length: 512,

            code_lifetime: 60,
            token_lifetime: 3600,
            refresh_lifetime: 30 * 86400,
            leeway: 60,

            poll_interval: 5.0,
            request_timeout: 30.0,
            discovery_timeout: 30.0,
        }
    }
}

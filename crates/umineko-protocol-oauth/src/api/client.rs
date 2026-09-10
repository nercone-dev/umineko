use alloc::string::String;
use crate::errors::OAuthError;
use crate::types::{OAuthGrant, OAuthToken, OAuthScope, OAuthClientType, OAuthLimits};
use crate::helpers::pkce::{PKCE, PKCEMethod};
use crate::helpers::discovery::OAuthMetadata;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthClientConfig {
    pub client_id: String,
    pub client_secret: Option<String>,
    pub client_type: OAuthClientType,

    pub issuer: String,
    pub redirect_uri: String,
    pub scope: OAuthScope,

    pub pkce: PKCEMethod,
    pub discovery: bool,
    pub auto_refresh: bool,
}

impl Default for OAuthClientConfig {
    fn default() -> Self {
        Self {
            client_id: String::new(),
            client_secret: None,
            client_type: OAuthClientType::Public,

            issuer: String::new(),
            redirect_uri: String::new(),
            scope: OAuthScope::default(),

            pkce: PKCEMethod::S256,
            discovery: true,
            auto_refresh: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct OAuthClient {
    pub config: OAuthClientConfig,
    pub limits: OAuthLimits,
    pub metadata: Option<OAuthMetadata>,
}

impl OAuthClient {
    pub fn new(config: OAuthClientConfig, limits: OAuthLimits) -> Self {
        todo!()
    }

    pub async fn discover(&mut self) -> Result<&OAuthMetadata, OAuthError> {
        todo!()
    }

    pub fn authorize(&self, seed: &[u8]) -> Result<(String, String, PKCE), OAuthError> {
        todo!()
    }

    pub fn callback(&self, url: &str, state: &str) -> Result<String, OAuthError> {
        todo!()
    }

    pub async fn exchange(&self, grant: OAuthGrant) -> Result<OAuthToken, OAuthError> {
        todo!()
    }

    pub async fn refresh(&self, token: &OAuthToken) -> Result<OAuthToken, OAuthError> {
        todo!()
    }

    pub async fn revoke(&self, token: &OAuthToken) -> Result<(), OAuthError> {
        todo!()
    }

    pub async fn device(&self) -> Result<(String, String, f64), OAuthError> {
        todo!()
    }
}

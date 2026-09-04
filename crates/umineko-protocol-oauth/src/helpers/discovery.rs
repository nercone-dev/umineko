use alloc::{string::String, vec::Vec};
use crate::errors::OAuthError;
use crate::types::OAuthLimits;
use crate::helpers::pkce::PKCEMethod;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthMetadata {
    pub issuer: String,
    pub authorization_endpoint: Option<String>,
    pub token_endpoint: Option<String>,
    pub device_authorization_endpoint: Option<String>,
    pub revocation_endpoint: Option<String>,
    pub introspection_endpoint: Option<String>,
    pub jwks_uri: Option<String>,

    pub scopes_supported: Vec<String>,
    pub grant_types_supported: Vec<String>,
    pub response_types_supported: Vec<String>,
    pub code_challenge_methods_supported: Vec<PKCEMethod>,
}

impl OAuthMetadata {
    pub const WELL_KNOWN_PATH: &'static str = "/.well-known/oauth-authorization-server";
    pub const OPENID_PATH: &'static str = "/.well-known/openid-configuration";

    pub fn parse(body: &[u8], limits: OAuthLimits) -> Result<Self, OAuthError> {
        todo!()
    }

    pub fn discovery_url(issuer: &str) -> Result<String, OAuthError> {
        todo!()
    }

    pub fn validate(&self, issuer: &str) -> Result<(), OAuthError> {
        todo!()
    }

    pub fn requires_pkce(&self) -> bool {
        todo!()
    }
}

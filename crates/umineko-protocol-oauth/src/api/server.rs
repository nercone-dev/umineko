use alloc::{string::String, vec::Vec};
use crate::errors::OAuthError;
use crate::types::{OAuthScope, OAuthLimits};
use crate::helpers::pkce::PKCEMethod;
use crate::protocol::exchange::OAuthExchange;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthServerConfig {
    pub issuer: String,
    pub grants: Vec<String>,
    pub scopes: OAuthScope,
    pub pkce_methods: Vec<PKCEMethod>,

    pub require_pkce: bool,
    pub strict_redirect_uri: bool,
    pub rotate_refresh_tokens: bool,
}

impl Default for OAuthServerConfig {
    fn default() -> Self {
        Self {
            issuer: String::new(),
            grants: Vec::new(),
            scopes: OAuthScope::default(),
            pkce_methods: [PKCEMethod::S256].to_vec(),

            require_pkce: true,
            strict_redirect_uri: true,
            rotate_refresh_tokens: true,
        }
    }
}

///
///
pub trait OAuthHandler {
    async fn on_exchange(&self, exchange: &mut OAuthExchange);
}

#[derive(Debug, Clone, Default)]
pub struct OAuthServer {
    pub config: OAuthServerConfig,
    pub limits: OAuthLimits,
}

impl OAuthServer {
    pub fn new(config: OAuthServerConfig, limits: OAuthLimits) -> Self {
        todo!()
    }

    pub async fn serve<H: OAuthHandler>(&self, handler: H) -> Result<(), OAuthError> {
        todo!()
    }

    pub fn run<H: OAuthHandler>(&self, handler: H, workers: usize) -> Result<(), OAuthError> {
        todo!()
    }
}

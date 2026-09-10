use alloc::string::String;
use crate::errors::{OAuthError, OAuthErrorCode};
use crate::types::{OAuthToken, OAuthScope, OAuthClientType, OAuthLimits};

#[derive(Debug)]
pub struct OAuthExchange {
    client_id: String,
    client_type: OAuthClientType,
    scope: OAuthScope,
    limits: OAuthLimits,
}

impl OAuthExchange {
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    pub fn client_type(&self) -> OAuthClientType {
        self.client_type
    }

    pub fn scope(&self) -> &OAuthScope {
        &self.scope
    }

    pub fn limits(&self) -> OAuthLimits {
        self.limits
    }

    pub async fn grant(&mut self, token: OAuthToken) -> Result<(), OAuthError> {
        todo!()
    }

    pub async fn restrict(&mut self, scope: OAuthScope) -> Result<(), OAuthError> {
        todo!()
    }

    pub async fn redirect(&mut self, code: &str) -> Result<(), OAuthError> {
        todo!()
    }

    pub async fn reject(&mut self, code: OAuthErrorCode, description: Option<&str>) -> Result<(), OAuthError> {
        todo!()
    }

    pub async fn introspect(&mut self, active: bool, scope: Option<OAuthScope>) -> Result<(), OAuthError> {
        todo!()
    }
}

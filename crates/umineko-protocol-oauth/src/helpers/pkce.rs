use alloc::string::String;
use crate::errors::OAuthError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PKCEMethod {
    Plain,
    S256,
}

impl PKCEMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Plain => "plain",
            Self::S256 => "S256",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        todo!()
    }

    pub fn secure(&self) -> bool {
        matches!(self, Self::S256)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PKCE {
    pub method: PKCEMethod,
    pub verifier: String,
    pub challenge: String,
}

impl PKCE {
    pub const MINIMUM_VERIFIER_LENGTH: usize = 43;
    pub const MAXIMUM_VERIFIER_LENGTH: usize = 128;

    pub fn generate(method: PKCEMethod, seed: &[u8]) -> Result<Self, OAuthError> {
        todo!()
    }

    pub fn derive(method: PKCEMethod, verifier: &str) -> Result<String, OAuthError> {
        todo!()
    }

    pub fn verify(method: PKCEMethod, verifier: &str, challenge: &str) -> Result<(), OAuthError> {
        todo!()
    }
}

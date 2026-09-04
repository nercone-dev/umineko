//! OAuth.

#![no_std]
#![allow(async_fn_in_trait)]

extern crate alloc;

pub mod api {
    pub mod client;
    pub mod server;

    pub use client::{OAuthClient, OAuthClientConfig};
    pub use server::{OAuthServer, OAuthServerConfig, OAuthHandler};
}

pub mod helpers {
    pub mod pkce;
    pub mod discovery;

    pub use pkce::{PKCE, PKCEMethod};
    pub use discovery::{OAuthMetadata};
}

pub mod protocol {
    pub mod exchange;

    pub use exchange::{OAuthExchange};
}

pub mod errors;
pub mod types;

pub use errors::{OAuthError, OAuthErrorCode};
pub use types::{OAuthGrant, OAuthToken, OAuthTokenType, OAuthScope, OAuthClientType, OAuthLimits};

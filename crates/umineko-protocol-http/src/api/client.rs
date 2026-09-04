use alloc::{string::String, vec::Vec, sync::Arc};
use core::future::poll_fn;
use crate::errors::HTTPError;
use crate::types::{HTTPVersion, HTTPMethod, HTTPBody, HTTPHeaders, HTTPMessage, HTTPLimits};
use crate::helpers::cookie::HTTPCookies;
use crate::helpers::dns::HTTPSRecordStore;
use crate::helpers::hsts::HSTSStore;
use crate::protocol::base::HTTPConnection;
#[cfg(feature = "websocket")]
use crate::protocol::ws::WSConnection;
use crate::provider::{HTTPProviderRequest, HTTPProviders};

use umineko_url::URL;
use umineko_protocol_tls::{TLSVersion, TLSGroup, TLSCipher};
use umineko_helpers::provider::{ProviderBackend, ProviderOpening};

#[derive(Debug, Clone, PartialEq)]
pub struct HTTPClientConfig {
    pub versions: Vec<HTTPVersion>,

    pub tls: bool,
    pub tls_versions: Vec<TLSVersion>,
    pub tls_groups:   Vec<TLSGroup>,
    pub tls_ciphers:  Vec<TLSCipher>,

    pub max_redirects: u8,
    pub cookies: bool,
    pub hsts: bool,
}

impl Default for HTTPClientConfig {
    fn default() -> Self {
        Self {
            versions: [HTTPVersion::V1_0, HTTPVersion::V1_1, HTTPVersion::V2_0, HTTPVersion::V3_0].to_vec(),

            tls: true,
            tls_versions: [TLSVersion::V1_2, TLSVersion::V1_3].to_vec(),
            tls_groups: [TLSGroup::X25519MLKEM768, TLSGroup::SECP384R1MLKEM1024, TLSGroup::SECP256R1MLKEM768, TLSGroup::MLKEM1024, TLSGroup::MLKEM768, TLSGroup::X25519, TLSGroup::PRIME256V1, TLSGroup::SECP384R1].to_vec(),
            tls_ciphers: [TLSCipher::TLS_AES_256_GCM_SHA384, TLSCipher::TLS_AES_128_GCM_SHA256, TLSCipher::TLS_CHACHA20_POLY1305_SHA256, TLSCipher::ECDHE_ECDSA_AES256_GCM_SHA384, TLSCipher::ECDHE_ECDSA_AES128_GCM_SHA256, TLSCipher::ECDHE_ECDSA_CHACHA20_POLY1305, TLSCipher::ECDHE_RSA_AES256_GCM_SHA384, TLSCipher::ECDHE_RSA_AES128_GCM_SHA256, TLSCipher::ECDHE_RSA_CHACHA20_POLY1305].to_vec(),

            max_redirects: 10,
            cookies: true,
            hsts: true,
        }
    }
}

pub struct HTTPClient {
    pub config: HTTPClientConfig,
    pub limits: HTTPLimits,
    pub cookies: Option<Arc<HTTPCookies>>,
    pub hsts: Option<Arc<HSTSStore>>,
    pub records: Option<Arc<HTTPSRecordStore>>,
}

impl Default for HTTPClient {
    fn default() -> Self {
        todo!()
    }
}

impl HTTPClient {
    pub fn new(config: HTTPClientConfig, limits: HTTPLimits) -> Self {
        todo!()
    }

    pub async fn request(&self, connection: &mut HTTPConnection, request: HTTPMessage) -> Result<HTTPMessage, HTTPError> {
        todo!()
    }

    pub async fn open(&self, url: &URL) -> Result<HTTPConnection, HTTPError> {
        todo!()
    }

    pub async fn fetch(&self, method: HTTPMethod, url: &str, headers: Option<HTTPHeaders>, body: Option<HTTPBody>) -> Result<HTTPMessage, HTTPError> {
        let target = URL::parse(url).map_err(|_| HTTPError::Target(String::from(url)))?;
        let mut request = HTTPMessage::request(method, &target.target());
        request.headers = headers;
        request.body = body;
        match HTTPProviders::open(&HTTPProviderRequest { url: &target, message: &request, config: &self.config, limits: &self.limits })? {
            Some(ProviderOpening { provider, handle }) => {
                let backend = ProviderBackend::Handle { provider: provider.clone(), handle };
                let response = poll_fn(|cx| provider.poll_response(handle, cx)).await?;
                drop(backend);
                Ok(response)
            }
            None => todo!(),
        }
    }

    pub async fn get(&self, url: &str) -> Result<HTTPMessage, HTTPError> {
        self.fetch(HTTPMethod::GET, url, None, None).await
    }

    pub async fn head(&self, url: &str) -> Result<HTTPMessage, HTTPError> {
        self.fetch(HTTPMethod::HEAD, url, None, None).await
    }

    pub async fn post(&self, url: &str, body: HTTPBody) -> Result<HTTPMessage, HTTPError> {
        self.fetch(HTTPMethod::POST, url, None, Some(body)).await
    }

    pub async fn put(&self, url: &str, body: HTTPBody) -> Result<HTTPMessage, HTTPError> {
        self.fetch(HTTPMethod::PUT, url, None, Some(body)).await
    }

    pub async fn patch(&self, url: &str, body: HTTPBody) -> Result<HTTPMessage, HTTPError> {
        self.fetch(HTTPMethod::PATCH, url, None, Some(body)).await
    }

    pub async fn delete(&self, url: &str) -> Result<HTTPMessage, HTTPError> {
        self.fetch(HTTPMethod::DELETE, url, None, None).await
    }

    pub async fn options(&self, url: &str) -> Result<HTTPMessage, HTTPError> {
        self.fetch(HTTPMethod::OPTIONS, url, None, None).await
    }

    #[cfg(feature = "websocket")]
    pub async fn websocket(&self, url: &str, protocols: &[String]) -> Result<WSConnection, HTTPError> {
        todo!()
    }
}


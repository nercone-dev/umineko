use alloc::{string::String, vec::Vec};
use crate::errors::HTTPError;
use crate::types::{HTTPPort, HTTPVersion, HTTPRole, HTTPLimits};
use crate::protocol::base::HTTPConnection;

use umineko_protocol_tls::{TLSVersion, TLSGroup, TLSCipher};

#[derive(Debug, Clone, PartialEq)]
pub struct HTTPServerConfig {
    pub versions: Vec<HTTPVersion>,
    pub role: HTTPRole,

    pub tls: bool,
    pub tls_versions: Vec<TLSVersion>,
    pub tls_groups:   Vec<TLSGroup>,
    pub tls_ciphers:  Vec<TLSCipher>,

    pub keepalive: bool,
    pub upgrade: bool,
    pub compress: bool,
}

impl Default for HTTPServerConfig {
    fn default() -> Self {
        Self {
            versions: [HTTPVersion::V1_0, HTTPVersion::V1_1, HTTPVersion::V2_0, HTTPVersion::V3_0].to_vec(),
            role: HTTPRole::Origin,

            tls: true,
            tls_versions: [TLSVersion::V1_2, TLSVersion::V1_3].to_vec(),
            tls_groups: [TLSGroup::X25519MLKEM768, TLSGroup::SECP384R1MLKEM1024, TLSGroup::SECP256R1MLKEM768, TLSGroup::X25519, TLSGroup::PRIME256V1, TLSGroup::SECP384R1].to_vec(),
            tls_ciphers: [TLSCipher::TLS_AES_256_GCM_SHA384, TLSCipher::TLS_AES_128_GCM_SHA256, TLSCipher::TLS_CHACHA20_POLY1305_SHA256, TLSCipher::ECDHE_ECDSA_AES256_GCM_SHA384, TLSCipher::ECDHE_RSA_AES256_GCM_SHA384].to_vec(),

            keepalive: true,
            upgrade: true,
            compress: true,
        }
    }
}

///
///
pub trait HTTPHandler {
    async fn on_connection(&self, connection: &mut HTTPConnection);
}

#[derive(Clone, Default)]
pub struct HTTPServer {
    pub config: HTTPServerConfig,
    pub limits: HTTPLimits,
}

impl HTTPServer {
    pub fn new(config: HTTPServerConfig, limits: HTTPLimits) -> Self {
        todo!()
    }

    pub fn application_protocols(&self) -> Vec<String> {
        todo!()
    }

    pub async fn serve<H: HTTPHandler>(&self, handler: H, ports: &[HTTPPort]) -> Result<(), HTTPError> {
        todo!()
    }

    pub fn run<H: HTTPHandler>(&self, handler: H, ports: &[HTTPPort], workers: usize) -> Result<(), HTTPError> {
        todo!()
    }
}

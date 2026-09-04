use alloc::{string::String, vec::Vec};
use crate::errors::TLSError;
use crate::types::{TLSVersion, TLSGroup, TLSCipher, TLSSignatureScheme, TLSLimits};
use crate::helpers::certificate::TLSCertificateChain;
use crate::helpers::session::TLSSessionStore;
use crate::protocol::base::TLSConnection;
use crate::provider::{TLSProviderRequest, TLSProviders};
use umineko_helpers::provider::ProviderOpening;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TLSClientConfig {
    pub versions: Vec<TLSVersion>,
    pub groups: Vec<TLSGroup>,
    pub ciphers: Vec<TLSCipher>,
    pub signature_schemes: Vec<TLSSignatureScheme>,

    pub application_protocols: Vec<String>,
    pub server_name: Option<String>,

    pub verify: bool,
    pub verify_name: bool,
    pub verify_revocation: bool,

    pub certificates: Option<TLSCertificateChain>,

    pub resume: bool,
    pub early_data: bool,
    pub encrypted_client_hello: bool,
}

impl Default for TLSClientConfig {
    fn default() -> Self {
        Self {
            versions: [TLSVersion::V1_3, TLSVersion::V1_2].to_vec(),
            groups: [TLSGroup::X25519MLKEM768, TLSGroup::SECP384R1MLKEM1024, TLSGroup::SECP256R1MLKEM768, TLSGroup::X25519, TLSGroup::PRIME256V1, TLSGroup::SECP384R1].to_vec(),
            ciphers: [TLSCipher::TLS_AES_256_GCM_SHA384, TLSCipher::TLS_AES_128_GCM_SHA256, TLSCipher::TLS_CHACHA20_POLY1305_SHA256, TLSCipher::ECDHE_ECDSA_AES256_GCM_SHA384, TLSCipher::ECDHE_RSA_AES256_GCM_SHA384].to_vec(),
            signature_schemes: [TLSSignatureScheme::ECDSA_SECP256R1_SHA256, TLSSignatureScheme::ED25519, TLSSignatureScheme::RSA_PSS_RSAE_SHA256, TLSSignatureScheme::MLDSA65].to_vec(),

            application_protocols: Vec::new(),
            server_name: None,

            verify: true,
            verify_name: true,
            verify_revocation: true,

            certificates: None,

            resume: true,
            early_data: false,
            encrypted_client_hello: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TLSClient {
    pub config: TLSClientConfig,
    pub limits: TLSLimits,
    pub sessions: TLSSessionStore,
}

impl TLSClient {
    pub fn new(config: TLSClientConfig, limits: TLSLimits) -> Self {
        todo!()
    }

    pub async fn connect(&self, name: &str) -> Result<TLSConnection, TLSError> {
        match TLSProviders::open(&TLSProviderRequest::Client { name, config: &self.config, limits: &self.limits })? {
            Some(ProviderOpening { provider, handle }) => TLSConnection::from_provider(provider, handle, self.limits),
            None => todo!(),
        }
    }
}


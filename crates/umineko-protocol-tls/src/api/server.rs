use alloc::{string::String, vec::Vec};
use crate::errors::TLSError;
use crate::types::{TLSVersion, TLSGroup, TLSCipher, TLSSignatureScheme, TLSLimits};
use crate::helpers::certificate::TLSCertificateChain;
use crate::helpers::session::TLSSessionStore;
use crate::protocol::base::TLSConnection;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TLSServerConfig {
    pub versions: Vec<TLSVersion>,
    pub groups: Vec<TLSGroup>,
    pub ciphers: Vec<TLSCipher>,
    pub signature_schemes: Vec<TLSSignatureScheme>,

    pub application_protocols: Vec<String>,

    pub certificates: Vec<(String, TLSCertificateChain)>,

    pub verify_client: bool,
    pub require_client_certificate: bool,

    pub issue_tickets: bool,
    pub early_data: bool,
}

impl Default for TLSServerConfig {
    fn default() -> Self {
        Self {
            versions: [TLSVersion::V1_3, TLSVersion::V1_2].to_vec(),
            groups: [TLSGroup::X25519MLKEM768, TLSGroup::SECP384R1MLKEM1024, TLSGroup::SECP256R1MLKEM768, TLSGroup::X25519, TLSGroup::PRIME256V1, TLSGroup::SECP384R1].to_vec(),
            ciphers: [TLSCipher::TLS_AES_256_GCM_SHA384, TLSCipher::TLS_AES_128_GCM_SHA256, TLSCipher::TLS_CHACHA20_POLY1305_SHA256, TLSCipher::ECDHE_ECDSA_AES256_GCM_SHA384, TLSCipher::ECDHE_RSA_AES256_GCM_SHA384].to_vec(),
            signature_schemes: [TLSSignatureScheme::ECDSA_SECP256R1_SHA256, TLSSignatureScheme::ED25519, TLSSignatureScheme::RSA_PSS_RSAE_SHA256, TLSSignatureScheme::MLDSA65].to_vec(),

            application_protocols: Vec::new(),

            certificates: Vec::new(),

            verify_client: false,
            require_client_certificate: false,

            issue_tickets: true,
            early_data: false,
        }
    }
}

///
pub trait TLSHandler {
    async fn on_connection(&self, connection: &mut TLSConnection);
}

#[derive(Debug, Clone)]
pub struct TLSServer {
    pub config: TLSServerConfig,
    pub limits: TLSLimits,
    pub sessions: TLSSessionStore,
}

impl TLSServer {
    pub fn new(config: TLSServerConfig, limits: TLSLimits) -> Self {
        todo!()
    }

    pub fn certificate(&self, name: Option<&str>) -> Option<&TLSCertificateChain> {
        todo!()
    }

    pub async fn serve<H: TLSHandler>(&self, handler: H) -> Result<(), TLSError> {
        todo!()
    }

    pub fn run<H: TLSHandler>(&self, handler: H, workers: usize) -> Result<(), TLSError> {
        todo!()
    }
}

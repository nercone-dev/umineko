use alloc::{string::String, vec::Vec};
use crate::errors::KerberosError;
use crate::types::{KerberosTransport, KerberosEncryptionType, KerberosPrincipal, KerberosChecksumType, KerberosLimits};
use crate::helpers::key::KerberosKey;
use crate::helpers::keytab::KerberosKeytab;
use crate::helpers::credentials::{KerberosCredentials, KerberosCredentialCache};
use crate::protocol::messages::KerberosAPRequest;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KerberosClientConfig {
    pub realm: String,
    pub servers: Vec<String>,
    pub transports: Vec<KerberosTransport>,
    pub encryption_types: Vec<KerberosEncryptionType>,

    pub forwardable: bool,
    pub renewable: bool,
    pub canonicalize: bool,
    pub allow_deprecated: bool,
}

impl Default for KerberosClientConfig {
    fn default() -> Self {
        Self {
            realm: String::new(),
            servers: Vec::new(),
            transports: [KerberosTransport::UDP, KerberosTransport::TCP].to_vec(),
            encryption_types: [KerberosEncryptionType::AES256_CTS_HMAC_SHA384_192, KerberosEncryptionType::AES128_CTS_HMAC_SHA256_128, KerberosEncryptionType::AES256_CTS_HMAC_SHA1_96, KerberosEncryptionType::AES128_CTS_HMAC_SHA1_96].to_vec(),

            forwardable: false,
            renewable: false,
            canonicalize: true,
            allow_deprecated: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct KerberosClient {
    pub config: KerberosClientConfig,
    pub limits: KerberosLimits,
    pub cache: KerberosCredentialCache,
}

impl KerberosClient {
    pub fn new(config: KerberosClientConfig, limits: KerberosLimits) -> Self {
        todo!()
    }

    pub async fn authenticate(&mut self, client: &KerberosPrincipal, password: &[u8]) -> Result<KerberosCredentials, KerberosError> {
        todo!()
    }

    pub async fn authenticate_with_keytab(&mut self, client: &KerberosPrincipal, keytab: &KerberosKeytab) -> Result<KerberosCredentials, KerberosError> {
        todo!()
    }

    pub async fn request_ticket(&mut self, credentials: &KerberosCredentials, server: &KerberosPrincipal) -> Result<KerberosCredentials, KerberosError> {
        todo!()
    }

    pub fn application_request(&self, credentials: &KerberosCredentials, now: u64, subkey: Option<KerberosKey>, checksum: Option<(KerberosChecksumType, Vec<u8>)>) -> Result<KerberosAPRequest, KerberosError> {
        todo!()
    }
}

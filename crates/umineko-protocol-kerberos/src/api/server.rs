use alloc::{string::String, vec::Vec};
use crate::errors::KerberosError;
use crate::types::{KerberosTransport, KerberosEncryptionType, KerberosLimits};
use crate::protocol::base::KerberosConnection;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KerberosServerConfig {
    pub realm: String,
    pub transports: Vec<KerberosTransport>,
    pub encryption_types: Vec<KerberosEncryptionType>,

    pub require_preauthentication: bool,
    pub allow_deprecated: bool,
}

impl Default for KerberosServerConfig {
    fn default() -> Self {
        Self {
            realm: String::new(),
            transports: [KerberosTransport::UDP, KerberosTransport::TCP].to_vec(),
            encryption_types: [KerberosEncryptionType::AES256_CTS_HMAC_SHA384_192, KerberosEncryptionType::AES128_CTS_HMAC_SHA256_128, KerberosEncryptionType::AES256_CTS_HMAC_SHA1_96, KerberosEncryptionType::AES128_CTS_HMAC_SHA1_96].to_vec(),

            require_preauthentication: true,
            allow_deprecated: false,
        }
    }
}

///
pub trait KerberosHandler {
    async fn on_connection(&self, connection: &mut KerberosConnection);
}

#[derive(Debug, Clone, Default)]
pub struct KerberosServer {
    pub config: KerberosServerConfig,
    pub limits: KerberosLimits,
}

impl KerberosServer {
    pub fn new(config: KerberosServerConfig, limits: KerberosLimits) -> Self {
        todo!()
    }

    pub async fn serve<H: KerberosHandler>(&self, handler: H) -> Result<(), KerberosError> {
        todo!()
    }

    pub fn run<H: KerberosHandler>(&self, handler: H, workers: usize) -> Result<(), KerberosError> {
        todo!()
    }
}

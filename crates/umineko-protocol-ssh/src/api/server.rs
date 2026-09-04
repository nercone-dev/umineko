use alloc::{string::String, vec::Vec};
use crate::errors::SSHError;
use crate::types::SSHLimits;
use crate::helpers::kex::SSHKeyExchange;
use crate::helpers::cipher::SSHCipher;
use crate::helpers::mac::{SSHMac, SSHCompression};
use crate::helpers::key::SSHKey;
use crate::protocol::authentication::SSHAuthenticationMethod;
use crate::protocol::base::SSHConnection;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SSHServerConfig {
    pub host_keys: Vec<SSHKey>,
    pub key_exchanges: Vec<SSHKeyExchange>,
    pub ciphers: Vec<SSHCipher>,
    pub macs: Vec<SSHMac>,
    pub compressions: Vec<SSHCompression>,
    pub methods: Vec<SSHAuthenticationMethod>,

    pub forwarding: bool,
    pub allow_privileged: bool,
    pub software: String,
}

impl Default for SSHServerConfig {
    fn default() -> Self {
        Self {
            host_keys: Vec::new(),
            key_exchanges: [SSHKeyExchange::MLKEM768_X25519_SHA256, SSHKeyExchange::CURVE25519_SHA256].to_vec(),
            ciphers: [SSHCipher::CHACHA20_POLY1305, SSHCipher::AES256_GCM].to_vec(),
            macs: [SSHMac::Implicit, SSHMac::HMAC_SHA2_256_ETM].to_vec(),
            compressions: [SSHCompression::None].to_vec(),
            methods: [SSHAuthenticationMethod::PublicKey].to_vec(),

            forwarding: false,
            allow_privileged: false,
            software: String::new(),
        }
    }
}

///
pub trait SSHHandler {
    async fn on_connection(&self, connection: &mut SSHConnection);
}

#[derive(Debug, Clone, Default)]
pub struct SSHServer {
    pub config: SSHServerConfig,
    pub limits: SSHLimits,
}

impl SSHServer {
    pub fn new(config: SSHServerConfig, limits: SSHLimits) -> Self {
        todo!()
    }

    pub async fn serve<H: SSHHandler>(&self, handler: H) -> Result<(), SSHError> {
        todo!()
    }

    pub fn run<H: SSHHandler>(&self, handler: H, workers: usize) -> Result<(), SSHError> {
        todo!()
    }
}

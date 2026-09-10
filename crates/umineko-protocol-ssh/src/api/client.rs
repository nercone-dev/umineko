use alloc::{string::String, vec::Vec};
use crate::errors::SSHError;
use crate::types::SSHLimits;
use crate::helpers::kex::SSHKeyExchange;
use crate::helpers::cipher::SSHCipher;
use crate::helpers::mac::{SSHMac, SSHCompression};
use crate::helpers::key::{SSHKey, SSHKnownHosts};
use crate::protocol::authentication::SSHAuthenticationMethod;
use crate::protocol::connection::SSHChannel;
use crate::protocol::base::SSHConnection;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SSHClientConfig {
    pub username: String,
    pub key_exchanges: Vec<SSHKeyExchange>,
    pub ciphers: Vec<SSHCipher>,
    pub macs: Vec<SSHMac>,
    pub compressions: Vec<SSHCompression>,
    pub methods: Vec<SSHAuthenticationMethod>,

    pub keys: Vec<SSHKey>,
    pub password: Option<String>,

    pub verify_host_key: bool,
    pub accept_unknown_host_key: bool,
}

impl Default for SSHClientConfig {
    fn default() -> Self {
        Self {
            username: String::new(),
            key_exchanges: [SSHKeyExchange::MLKEM768_X25519_SHA256, SSHKeyExchange::CURVE25519_SHA256, SSHKeyExchange::ECDH_SHA2_NISTP256].to_vec(),
            ciphers: [SSHCipher::CHACHA20_POLY1305, SSHCipher::AES256_GCM, SSHCipher::AES128_GCM].to_vec(),
            macs: [SSHMac::Implicit, SSHMac::HMAC_SHA2_256_ETM].to_vec(),
            compressions: [SSHCompression::None].to_vec(),
            methods: [SSHAuthenticationMethod::PublicKey, SSHAuthenticationMethod::KeyboardInteractive, SSHAuthenticationMethod::Password].to_vec(),

            keys: Vec::new(),
            password: None,

            verify_host_key: true,
            accept_unknown_host_key: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SSHClient {
    pub config: SSHClientConfig,
    pub limits: SSHLimits,
    pub known_hosts: SSHKnownHosts,
}

impl SSHClient {
    pub fn new(config: SSHClientConfig, limits: SSHLimits) -> Self {
        todo!()
    }

    pub async fn connect(&self, host: &str, port: u16) -> Result<SSHConnection, SSHError> {
        todo!()
    }

    pub async fn shell(&self) -> Result<SSHChannel, SSHError> {
        todo!()
    }

    pub async fn execute(&self, command: &str) -> Result<(u32, Vec<u8>), SSHError> {
        todo!()
    }

    pub async fn subsystem(&self, name: &str) -> Result<SSHChannel, SSHError> {
        todo!()
    }

    pub async fn forward(&self, address: &str, port: u16) -> Result<SSHChannel, SSHError> {
        todo!()
    }
}


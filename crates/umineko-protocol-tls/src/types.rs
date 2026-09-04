use alloc::{string::String, vec::Vec};
use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TLSVersion {
    V1_0,
    V1_1,
    V1_2,
    V1_3,
}

impl TLSVersion {
    pub fn number(&self) -> u16 {
        match self {
            Self::V1_0 => 0x0301,
            Self::V1_1 => 0x0302,
            Self::V1_2 => 0x0303,
            Self::V1_3 => 0x0304,
        }
    }

    pub fn from_number(number: u16) -> Option<Self> {
        match number {
            0x0301 => Some(Self::V1_0),
            0x0302 => Some(Self::V1_1),
            0x0303 => Some(Self::V1_2),
            0x0304 => Some(Self::V1_3),
            _ => None,
        }
    }

    pub fn secure(&self) -> bool {
        matches!(self, Self::V1_2 | Self::V1_3)
    }

    pub fn negotiated_by_extension(&self) -> bool {
        matches!(self, Self::V1_3)
    }

    pub fn early_data(&self) -> bool {
        matches!(self, Self::V1_3)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::V1_0 => "TLSv1.0",
            Self::V1_1 => "TLSv1.1",
            Self::V1_2 => "TLSv1.2",
            Self::V1_3 => "TLSv1.3",
        }
    }
}

impl fmt::Display for TLSVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TLSRole {
    Client,
    Server,
}

impl TLSRole {
    pub fn peer(&self) -> Self {
        match self {
            Self::Client => Self::Server,
            Self::Server => Self::Client,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TLSGroup {
    X25519,
    X448,
    PRIME256V1,
    SECP384R1,
    SECP521R1,

    MLKEM512,
    MLKEM768,
    MLKEM1024,

    X25519MLKEM768,
    SECP256R1MLKEM768,
    SECP384R1MLKEM1024,
}

impl TLSGroup {
    pub fn number(&self) -> u16 {
        todo!()
    }

    pub fn from_number(number: u16) -> Option<Self> {
        todo!()
    }

    pub fn post_quantum(&self) -> bool {
        matches!(self, Self::MLKEM512 | Self::MLKEM768 | Self::MLKEM1024 | Self::X25519MLKEM768 | Self::SECP256R1MLKEM768 | Self::SECP384R1MLKEM1024)
    }

    pub fn hybrid(&self) -> bool {
        matches!(self, Self::X25519MLKEM768 | Self::SECP256R1MLKEM768 | Self::SECP384R1MLKEM1024)
    }

    pub fn public_key_size(&self) -> usize {
        todo!()
    }

    pub fn as_str(&self) -> &'static str {
        todo!()
    }

    pub fn from_name(name: &str) -> Option<Self> {
        todo!()
    }
}

impl fmt::Display for TLSGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TLSCipher {
    TLS_AES_128_GCM_SHA256,
    TLS_AES_256_GCM_SHA384,
    TLS_CHACHA20_POLY1305_SHA256,
    TLS_AES_128_CCM_SHA256,

    ECDHE_ECDSA_AES128_GCM_SHA256,
    ECDHE_ECDSA_AES256_GCM_SHA384,
    ECDHE_ECDSA_CHACHA20_POLY1305,
    ECDHE_RSA_AES128_GCM_SHA256,
    ECDHE_RSA_AES256_GCM_SHA384,
    ECDHE_RSA_CHACHA20_POLY1305,
}

impl TLSCipher {
    pub fn number(&self) -> u16 {
        todo!()
    }

    pub fn from_number(number: u16) -> Option<Self> {
        todo!()
    }

    pub fn versions(&self) -> &'static [TLSVersion] {
        todo!()
    }

    pub fn key_size(&self) -> usize {
        todo!()
    }

    pub fn nonce_size(&self) -> usize {
        todo!()
    }

    pub fn tag_size(&self) -> usize {
        todo!()
    }

    pub fn digest_size(&self) -> usize {
        todo!()
    }

    pub fn as_str(&self) -> &'static str {
        todo!()
    }

    pub fn from_name(name: &str) -> Option<Self> {
        todo!()
    }
}

impl fmt::Display for TLSCipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TLSSignatureScheme {
    ECDSA_SECP256R1_SHA256,
    ECDSA_SECP384R1_SHA384,
    ECDSA_SECP521R1_SHA512,
    ED25519,
    ED448,
    RSA_PSS_RSAE_SHA256,
    RSA_PSS_RSAE_SHA384,
    RSA_PSS_RSAE_SHA512,
    RSA_PKCS1_SHA256,
    RSA_PKCS1_SHA384,
    RSA_PKCS1_SHA512,
    MLDSA44,
    MLDSA65,
    MLDSA87,
}

impl TLSSignatureScheme {
    pub fn number(&self) -> u16 {
        todo!()
    }

    pub fn from_number(number: u16) -> Option<Self> {
        todo!()
    }

    pub fn post_quantum(&self) -> bool {
        matches!(self, Self::MLDSA44 | Self::MLDSA65 | Self::MLDSA87)
    }

    pub fn as_str(&self) -> &'static str {
        todo!()
    }
}

impl fmt::Display for TLSSignatureScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TLSExtension {
    ServerName(String),
    SupportedVersions(Vec<TLSVersion>),
    SupportedGroups(Vec<TLSGroup>),
    SignatureAlgorithms(Vec<TLSSignatureScheme>),
    ApplicationLayerProtocolNegotiation(Vec<String>),
    KeyShare(Vec<(TLSGroup, Vec<u8>)>),
    PreSharedKey(Vec<u8>),
    EarlyData,
    SessionTicket(Vec<u8>),
    EncryptedClientHello(Vec<u8>),
    QUICTransportParameters(Vec<u8>),
    Unknown { kind: u16, data: Vec<u8> },
}

impl TLSExtension {
    pub fn kind(&self) -> u16 {
        todo!()
    }

    pub fn allowed(&self, version: TLSVersion) -> bool {
        todo!()
    }

    pub fn encode(&self) -> Vec<u8> {
        todo!()
    }

    pub fn decode(kind: u16, data: &[u8]) -> Self {
        todo!()
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TLSLimits {
    pub max_record_size: u32,
    pub max_handshake_size: u32,
    pub max_extension_size: u32,
    pub max_extension_count: u16,
    pub max_certificate_size: u32,
    pub max_certificate_chain_length: u8,
    pub max_early_data_size: u32,

    pub max_connection_count: u64,
    pub max_session_count: u32,
    pub max_records_per_key: u64,
    pub max_retry_count: u8,

    pub handshake_timeout: f64,
    pub read_timeout: f64,
    pub write_timeout: f64,
    pub close_timeout: f64,
    pub session_lifetime: f64,
}

impl Default for TLSLimits {
    fn default() -> Self {
        Self {
            max_record_size: 16 * 1024,
            max_handshake_size: 64 * 1024,
            max_extension_size: 16 * 1024,
            max_extension_count: 64,
            max_certificate_size: 64 * 1024,
            max_certificate_chain_length: 10,
            max_early_data_size: 16 * 1024,

            max_connection_count: 1024,
            max_session_count: 4096,
            max_records_per_key: 1 << 24,
            max_retry_count: 1,

            handshake_timeout: 10.0,
            read_timeout: 30.0,
            write_timeout: 30.0,
            close_timeout: 5.0,
            session_lifetime: 86400.0,
        }
    }
}

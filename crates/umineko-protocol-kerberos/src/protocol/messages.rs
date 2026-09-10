use alloc::{string::String, vec::Vec};
use crate::errors::{KerberosError, KerberosErrorCode};
use crate::types::{KerberosVersion, KerberosMessageType, KerberosPrincipalName, KerberosPrincipal, KerberosEncryptionType, KerberosChecksumType, KerberosKeyUsage, KerberosLimits};
use crate::helpers::key::KerberosKey;
use crate::helpers::keytab::KerberosKeytab;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KerberosEncryptedData {
    pub encryption: KerberosEncryptionType,
    pub version: Option<u32>,
    pub cipher: Vec<u8>,
}

impl KerberosEncryptedData {
    pub fn encrypt(key: &KerberosKey, usage: KerberosKeyUsage, plaintext: &[u8], version: Option<u32>) -> Result<Self, KerberosError> {
        Ok(Self { encryption: key.encryption(), version, cipher: key.encrypt(usage, plaintext)? })
    }

    pub fn decrypt(&self, key: &KerberosKey, usage: KerberosKeyUsage) -> Result<Vec<u8>, KerberosError> {
        if key.encryption() != self.encryption {
            return Err(KerberosError::EncryptionType);
        }
        key.decrypt(usage, &self.cipher)
    }

    pub fn encode(&self) -> Result<Vec<u8>, KerberosError> {
        todo!()
    }

    pub fn decode(data: &[u8], limits: &KerberosLimits) -> Result<Self, KerberosError> {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KerberosTicket {
    pub version: KerberosVersion,
    pub realm: String,
    pub server: KerberosPrincipalName,
    pub encrypted: KerberosEncryptedData,
}

impl KerberosTicket {
    pub fn decrypt(&self, key: &KerberosKey, limits: &KerberosLimits) -> Result<KerberosTicketPart, KerberosError> {
        KerberosTicketPart::decode(&self.encrypted.decrypt(key, KerberosKeyUsage::TICKET)?, limits)
    }

    pub fn encode(&self) -> Result<Vec<u8>, KerberosError> {
        todo!()
    }

    pub fn decode(data: &[u8], limits: &KerberosLimits) -> Result<Self, KerberosError> {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KerberosTicketPart {
    pub flags: u32,
    pub key: KerberosKey,
    pub client: KerberosPrincipal,
    pub transited: (i32, Vec<u8>),
    pub authentication_time: u64,
    pub start_time: Option<u64>,
    pub end_time: u64,
    pub renew_until: Option<u64>,
    pub addresses: Vec<Vec<u8>>,
    pub authorization: Vec<(i32, Vec<u8>)>,
}

impl KerberosTicketPart {
    pub fn encode(&self) -> Result<Vec<u8>, KerberosError> {
        todo!()
    }

    pub fn decode(data: &[u8], limits: &KerberosLimits) -> Result<Self, KerberosError> {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KerberosAuthenticator {
    pub version: KerberosVersion,
    pub client: KerberosPrincipal,
    pub checksum: Option<(KerberosChecksumType, Vec<u8>)>,
    pub microseconds: u32,
    pub time: u64,
    pub subkey: Option<KerberosKey>,
    pub sequence: Option<u32>,
    pub authorization: Vec<(i32, Vec<u8>)>,
}

impl KerberosAuthenticator {
    pub fn encode(&self) -> Result<Vec<u8>, KerberosError> {
        todo!()
    }

    pub fn decode(data: &[u8], limits: &KerberosLimits) -> Result<Self, KerberosError> {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KerberosAPRequest {
    pub options: u32,
    pub ticket: KerberosTicket,
    pub authenticator: KerberosEncryptedData,
}

impl KerberosAPRequest {
    pub fn verify(&self, keytab: &KerberosKeytab, now: u64, limits: &KerberosLimits) -> Result<(KerberosTicketPart, KerberosAuthenticator), KerberosError> {
        todo!()
    }

    pub fn encode(&self) -> Result<Vec<u8>, KerberosError> {
        todo!()
    }

    pub fn decode(data: &[u8], limits: &KerberosLimits) -> Result<Self, KerberosError> {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KerberosAPReply {
    pub encrypted: KerberosEncryptedData,
}

impl KerberosAPReply {
    pub fn encode(&self) -> Result<Vec<u8>, KerberosError> {
        todo!()
    }

    pub fn decode(data: &[u8], limits: &KerberosLimits) -> Result<Self, KerberosError> {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KerberosKDCRequest {
    pub preauthentication: Vec<(i32, Vec<u8>)>,
    pub options: u32,
    pub client: Option<KerberosPrincipalName>,
    pub realm: String,
    pub server: Option<KerberosPrincipalName>,
    pub from: Option<u64>,
    pub till: u64,
    pub renew_until: Option<u64>,
    pub nonce: u32,
    pub encryption_types: Vec<KerberosEncryptionType>,
    pub addresses: Vec<Vec<u8>>,
    pub authorization: Option<KerberosEncryptedData>,
    pub tickets: Vec<KerberosTicket>,
}

impl KerberosKDCRequest {
    pub fn encode(&self) -> Result<Vec<u8>, KerberosError> {
        todo!()
    }

    pub fn decode(data: &[u8], limits: &KerberosLimits) -> Result<Self, KerberosError> {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KerberosKDCReply {
    pub preauthentication: Vec<(i32, Vec<u8>)>,
    pub realm: String,
    pub client: KerberosPrincipalName,
    pub ticket: KerberosTicket,
    pub encrypted: KerberosEncryptedData,
}

impl KerberosKDCReply {
    pub fn encode(&self) -> Result<Vec<u8>, KerberosError> {
        todo!()
    }

    pub fn decode(data: &[u8], limits: &KerberosLimits) -> Result<Self, KerberosError> {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KerberosSafe {
    pub data: Vec<u8>,
    pub time: Option<u64>,
    pub microseconds: Option<u32>,
    pub sequence: Option<u32>,
    pub sender: Vec<u8>,
    pub recipient: Option<Vec<u8>>,
    pub checksum: (KerberosChecksumType, Vec<u8>),
}

impl KerberosSafe {
    pub fn encode(&self) -> Result<Vec<u8>, KerberosError> {
        todo!()
    }

    pub fn decode(data: &[u8], limits: &KerberosLimits) -> Result<Self, KerberosError> {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KerberosPrivate {
    pub encrypted: KerberosEncryptedData,
}

impl KerberosPrivate {
    pub fn encode(&self) -> Result<Vec<u8>, KerberosError> {
        todo!()
    }

    pub fn decode(data: &[u8], limits: &KerberosLimits) -> Result<Self, KerberosError> {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KerberosCredential {
    pub tickets: Vec<KerberosTicket>,
    pub encrypted: KerberosEncryptedData,
}

impl KerberosCredential {
    pub fn encode(&self) -> Result<Vec<u8>, KerberosError> {
        todo!()
    }

    pub fn decode(data: &[u8], limits: &KerberosLimits) -> Result<Self, KerberosError> {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KerberosErrorMessage {
    pub code: KerberosErrorCode,
    pub client_time: Option<u64>,
    pub client_microseconds: Option<u32>,
    pub server_time: u64,
    pub server_microseconds: u32,
    pub client_realm: Option<String>,
    pub client_name: Option<KerberosPrincipalName>,
    pub server_realm: String,
    pub server_name: KerberosPrincipalName,
    pub text: Option<String>,
    pub data: Option<Vec<u8>>,
}

impl KerberosErrorMessage {
    pub fn encode(&self) -> Result<Vec<u8>, KerberosError> {
        todo!()
    }

    pub fn decode(data: &[u8], limits: &KerberosLimits) -> Result<Self, KerberosError> {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KerberosMessage {
    ASRequest(KerberosKDCRequest),
    ASReply(KerberosKDCReply),
    TGSRequest(KerberosKDCRequest),
    TGSReply(KerberosKDCReply),
    APRequest(KerberosAPRequest),
    APReply(KerberosAPReply),
    Safe(KerberosSafe),
    Private(KerberosPrivate),
    Credential(KerberosCredential),
    Error(KerberosErrorMessage),
}

impl KerberosMessage {
    pub fn message_type(&self) -> KerberosMessageType {
        match self {
            Self::ASRequest(_) => KerberosMessageType::ASRequest,
            Self::ASReply(_) => KerberosMessageType::ASReply,
            Self::TGSRequest(_) => KerberosMessageType::TGSRequest,
            Self::TGSReply(_) => KerberosMessageType::TGSReply,
            Self::APRequest(_) => KerberosMessageType::APRequest,
            Self::APReply(_) => KerberosMessageType::APReply,
            Self::Safe(_) => KerberosMessageType::Safe,
            Self::Private(_) => KerberosMessageType::Private,
            Self::Credential(_) => KerberosMessageType::Credential,
            Self::Error(_) => KerberosMessageType::Error,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, KerberosError> {
        todo!()
    }

    pub fn decode(data: &[u8], limits: &KerberosLimits) -> Result<Self, KerberosError> {
        todo!()
    }
}

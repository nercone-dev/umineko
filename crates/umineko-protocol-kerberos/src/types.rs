use alloc::{string::String, vec::Vec};
use core::fmt;
use crate::errors::KerberosError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum KerberosVersion {
    V5,
}

impl KerberosVersion {
    pub fn number(&self) -> u8 {
        match self {
            Self::V5 => 5,
        }
    }

    pub fn from_number(number: u8) -> Option<Self> {
        match number {
            5 => Some(Self::V5),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::V5 => "KerberosV5",
        }
    }
}

impl fmt::Display for KerberosVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KerberosTransport {
    UDP,
    TCP,
}

impl KerberosTransport {
    pub const PORT: u16 = 88;

    pub fn framed(&self) -> bool {
        matches!(self, Self::TCP)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::UDP => "UDP",
            Self::TCP => "TCP",
        }
    }
}

impl fmt::Display for KerberosTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KerberosMessageType {
    ASRequest,
    ASReply,
    TGSRequest,
    TGSReply,
    APRequest,
    APReply,
    Safe,
    Private,
    Credential,
    Error,
}

impl KerberosMessageType {
    pub const ALL: [Self; 10] = [Self::ASRequest, Self::ASReply, Self::TGSRequest, Self::TGSReply, Self::APRequest, Self::APReply, Self::Safe, Self::Private, Self::Credential, Self::Error];

    pub fn number(&self) -> u8 {
        match self {
            Self::ASRequest => 10,
            Self::ASReply => 11,
            Self::TGSRequest => 12,
            Self::TGSReply => 13,
            Self::APRequest => 14,
            Self::APReply => 15,
            Self::Safe => 20,
            Self::Private => 21,
            Self::Credential => 22,
            Self::Error => 30,
        }
    }

    pub fn from_number(number: u8) -> Option<Self> {
        Self::ALL.iter().copied().find(|kind| kind.number() == number)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ASRequest => "KRB_AS_REQ",
            Self::ASReply => "KRB_AS_REP",
            Self::TGSRequest => "KRB_TGS_REQ",
            Self::TGSReply => "KRB_TGS_REP",
            Self::APRequest => "KRB_AP_REQ",
            Self::APReply => "KRB_AP_REP",
            Self::Safe => "KRB_SAFE",
            Self::Private => "KRB_PRIV",
            Self::Credential => "KRB_CRED",
            Self::Error => "KRB_ERROR",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|kind| kind.as_str() == name)
    }
}

impl fmt::Display for KerberosMessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KerberosNameType {
    Unknown,
    Principal,
    ServiceInstance,
    ServiceHost,
    ServiceExtendedHost,
    UID,
    X500Principal,
    SMTPName,
    Enterprise,
    WellKnown,
}

impl KerberosNameType {
    pub const ALL: [Self; 10] = [Self::Unknown, Self::Principal, Self::ServiceInstance, Self::ServiceHost, Self::ServiceExtendedHost, Self::UID, Self::X500Principal, Self::SMTPName, Self::Enterprise, Self::WellKnown];

    pub fn number(&self) -> i32 {
        match self {
            Self::Unknown => 0,
            Self::Principal => 1,
            Self::ServiceInstance => 2,
            Self::ServiceHost => 3,
            Self::ServiceExtendedHost => 4,
            Self::UID => 5,
            Self::X500Principal => 6,
            Self::SMTPName => 7,
            Self::Enterprise => 10,
            Self::WellKnown => 11,
        }
    }

    pub fn from_number(number: i32) -> Option<Self> {
        Self::ALL.iter().copied().find(|kind| kind.number() == number)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Unknown => "NT-UNKNOWN",
            Self::Principal => "NT-PRINCIPAL",
            Self::ServiceInstance => "NT-SRV-INST",
            Self::ServiceHost => "NT-SRV-HST",
            Self::ServiceExtendedHost => "NT-SRV-XHST",
            Self::UID => "NT-UID",
            Self::X500Principal => "NT-X500-PRINCIPAL",
            Self::SMTPName => "NT-SMTP-NAME",
            Self::Enterprise => "NT-ENTERPRISE",
            Self::WellKnown => "NT-WELLKNOWN",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|kind| kind.as_str() == name)
    }
}

impl fmt::Display for KerberosNameType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KerberosPrincipalName {
    pub kind: KerberosNameType,
    pub components: Vec<String>,
}

impl KerberosPrincipalName {
    pub fn new(kind: KerberosNameType, components: Vec<String>) -> Self {
        Self { kind, components }
    }

    pub fn service(service: &str, host: &str) -> Self {
        Self { kind: KerberosNameType::ServiceHost, components: [String::from(service), String::from(host)].to_vec() }
    }

    pub fn matches(&self, other: &Self) -> bool {
        self.components == other.components
    }

    pub fn encode(&self) -> Result<Vec<u8>, KerberosError> {
        todo!()
    }

    pub fn decode(data: &[u8]) -> Result<Self, KerberosError> {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KerberosPrincipal {
    pub name: KerberosPrincipalName,
    pub realm: String,
}

impl KerberosPrincipal {
    pub const HOST_SERVICE: &'static str = "host";

    pub fn new(name: KerberosPrincipalName, realm: &str) -> Self {
        Self { name, realm: String::from(realm) }
    }

    pub fn host(machine: &str, realm: &str) -> Self {
        Self::new(KerberosPrincipalName::service(Self::HOST_SERVICE, machine), realm)
    }

    pub fn matches(&self, other: &Self) -> bool {
        self.realm == other.realm && self.name.matches(&other.name)
    }

    pub fn parse(text: &str) -> Result<Self, KerberosError> {
        todo!()
    }
}

impl fmt::Display for KerberosPrincipal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KerberosKeyUsage(pub u32);

impl KerberosKeyUsage {
    pub const AS_REQ_TIMESTAMP: Self = Self(1);
    pub const TICKET: Self = Self(2);
    pub const AS_REP_PART: Self = Self(3);
    pub const TGS_REQ_AUTHORIZATION_SESSION: Self = Self(4);
    pub const TGS_REQ_AUTHORIZATION_SUBKEY: Self = Self(5);
    pub const TGS_REQ_AUTHENTICATOR_CHECKSUM: Self = Self(6);
    pub const TGS_REQ_AUTHENTICATOR: Self = Self(7);
    pub const TGS_REP_PART_SESSION: Self = Self(8);
    pub const TGS_REP_PART_SUBKEY: Self = Self(9);
    pub const AP_REQ_AUTHENTICATOR_CHECKSUM: Self = Self(10);
    pub const AP_REQ_AUTHENTICATOR: Self = Self(11);
    pub const AP_REP_PART: Self = Self(12);
    pub const PRIV_PART: Self = Self(13);
    pub const CRED_PART: Self = Self(14);
    pub const SAFE_CHECKSUM: Self = Self(15);
    pub const AD_KDC_ISSUED_CHECKSUM: Self = Self(19);
    pub const APPLICATION_ENCRYPTION: Self = Self(1024);
    pub const APPLICATION_CHECKSUM: Self = Self(1025);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KerberosEncryptionTypeSpecification {
    pub number: i32,
    pub name: &'static str,
    pub key_size: Option<usize>,
    pub seed_size: Option<usize>,
    pub block_size: Option<usize>,
    pub message_block_size: Option<usize>,
    pub confounder_size: Option<usize>,
    pub integrity_size: Option<usize>,
    pub checksum: Option<KerberosChecksumType>,
    pub parameters: Option<&'static [u8]>,
    pub deprecated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KerberosEncryptionType {
    DES_CBC_CRC,
    DES_CBC_MD4,
    DES_CBC_MD5,
    DES3_CBC_MD5,
    DES3_CBC_SHA1,
    DSA_WITH_SHA1_CMS_OID,
    MD5_WITH_RSA_ENCRYPTION_CMS_OID,
    SHA1_WITH_RSA_ENCRYPTION_CMS_OID,
    RC2_CBC_ENV_OID,
    RSA_ENCRYPTION_ENV_OID,
    RSAES_OAEP_ENV_OID,
    DES_EDE3_CBC_ENV_OID,
    DES3_CBC_SHA1_KD,
    AES128_CTS_HMAC_SHA1_96,
    AES256_CTS_HMAC_SHA1_96,
    AES128_CTS_HMAC_SHA256_128,
    AES256_CTS_HMAC_SHA384_192,
    RC4_HMAC,
    RC4_HMAC_EXP,
    CAMELLIA128_CTS_CMAC,
    CAMELLIA256_CTS_CMAC,
    SUBKEY_KEYMATERIAL,
}

impl KerberosEncryptionType {
    pub const ALL: [Self; 22] = [
        Self::DES_CBC_CRC,
        Self::DES_CBC_MD4,
        Self::DES_CBC_MD5,
        Self::DES3_CBC_MD5,
        Self::DES3_CBC_SHA1,
        Self::DSA_WITH_SHA1_CMS_OID,
        Self::MD5_WITH_RSA_ENCRYPTION_CMS_OID,
        Self::SHA1_WITH_RSA_ENCRYPTION_CMS_OID,
        Self::RC2_CBC_ENV_OID,
        Self::RSA_ENCRYPTION_ENV_OID,
        Self::RSAES_OAEP_ENV_OID,
        Self::DES_EDE3_CBC_ENV_OID,
        Self::DES3_CBC_SHA1_KD,
        Self::AES128_CTS_HMAC_SHA1_96,
        Self::AES256_CTS_HMAC_SHA1_96,
        Self::AES128_CTS_HMAC_SHA256_128,
        Self::AES256_CTS_HMAC_SHA384_192,
        Self::RC4_HMAC,
        Self::RC4_HMAC_EXP,
        Self::CAMELLIA128_CTS_CMAC,
        Self::CAMELLIA256_CTS_CMAC,
        Self::SUBKEY_KEYMATERIAL,
    ];

    pub fn specification(&self) -> KerberosEncryptionTypeSpecification {
        match self {
            Self::DES_CBC_CRC => KerberosEncryptionTypeSpecification { number: 1, name: "des-cbc-crc", key_size: Some(8), seed_size: Some(8), block_size: Some(8), message_block_size: Some(8), confounder_size: Some(8), integrity_size: Some(4), checksum: Some(KerberosChecksumType::RSA_MD5_DES), parameters: Some(&[]), deprecated: true },
            Self::DES_CBC_MD4 => KerberosEncryptionTypeSpecification { number: 2, name: "des-cbc-md4", key_size: Some(8), seed_size: Some(8), block_size: Some(8), message_block_size: Some(8), confounder_size: Some(8), integrity_size: Some(16), checksum: Some(KerberosChecksumType::RSA_MD4_DES), parameters: Some(&[]), deprecated: true },
            Self::DES_CBC_MD5 => KerberosEncryptionTypeSpecification { number: 3, name: "des-cbc-md5", key_size: Some(8), seed_size: Some(8), block_size: Some(8), message_block_size: Some(8), confounder_size: Some(8), integrity_size: Some(16), checksum: Some(KerberosChecksumType::RSA_MD5_DES), parameters: Some(&[]), deprecated: true },
            Self::DES3_CBC_MD5 => KerberosEncryptionTypeSpecification { number: 5, name: "des3-cbc-md5", key_size: None, seed_size: None, block_size: None, message_block_size: None, confounder_size: None, integrity_size: None, checksum: None, parameters: None, deprecated: true },
            Self::DES3_CBC_SHA1 => KerberosEncryptionTypeSpecification { number: 7, name: "des3-cbc-sha1", key_size: None, seed_size: None, block_size: None, message_block_size: None, confounder_size: None, integrity_size: None, checksum: None, parameters: None, deprecated: true },
            Self::DSA_WITH_SHA1_CMS_OID => KerberosEncryptionTypeSpecification { number: 9, name: "dsaWithSHA1-CmsOID", key_size: None, seed_size: None, block_size: None, message_block_size: None, confounder_size: None, integrity_size: None, checksum: None, parameters: None, deprecated: false },
            Self::MD5_WITH_RSA_ENCRYPTION_CMS_OID => KerberosEncryptionTypeSpecification { number: 10, name: "md5WithRSAEncryption-CmsOID", key_size: None, seed_size: None, block_size: None, message_block_size: None, confounder_size: None, integrity_size: None, checksum: None, parameters: None, deprecated: false },
            Self::SHA1_WITH_RSA_ENCRYPTION_CMS_OID => KerberosEncryptionTypeSpecification { number: 11, name: "sha1WithRSAEncryption-CmsOID", key_size: None, seed_size: None, block_size: None, message_block_size: None, confounder_size: None, integrity_size: None, checksum: None, parameters: None, deprecated: false },
            Self::RC2_CBC_ENV_OID => KerberosEncryptionTypeSpecification { number: 12, name: "rc2CBC-EnvOID", key_size: None, seed_size: None, block_size: None, message_block_size: None, confounder_size: None, integrity_size: None, checksum: None, parameters: None, deprecated: false },
            Self::RSA_ENCRYPTION_ENV_OID => KerberosEncryptionTypeSpecification { number: 13, name: "rsaEncryption-EnvOID", key_size: None, seed_size: None, block_size: None, message_block_size: None, confounder_size: None, integrity_size: None, checksum: None, parameters: None, deprecated: false },
            Self::RSAES_OAEP_ENV_OID => KerberosEncryptionTypeSpecification { number: 14, name: "rsaES-OAEP-ENV-OID", key_size: None, seed_size: None, block_size: None, message_block_size: None, confounder_size: None, integrity_size: None, checksum: None, parameters: None, deprecated: false },
            Self::DES_EDE3_CBC_ENV_OID => KerberosEncryptionTypeSpecification { number: 15, name: "des-ede3-cbc-Env-OID", key_size: None, seed_size: None, block_size: None, message_block_size: None, confounder_size: None, integrity_size: None, checksum: None, parameters: None, deprecated: false },
            Self::DES3_CBC_SHA1_KD => KerberosEncryptionTypeSpecification { number: 16, name: "des3-cbc-sha1-kd", key_size: Some(24), seed_size: Some(21), block_size: Some(8), message_block_size: Some(8), confounder_size: Some(8), integrity_size: Some(20), checksum: Some(KerberosChecksumType::HMAC_SHA1_DES3_KD), parameters: Some(&[]), deprecated: true },
            Self::AES128_CTS_HMAC_SHA1_96 => KerberosEncryptionTypeSpecification { number: 17, name: "aes128-cts-hmac-sha1-96", key_size: Some(16), seed_size: Some(16), block_size: Some(16), message_block_size: Some(1), confounder_size: Some(16), integrity_size: Some(12), checksum: Some(KerberosChecksumType::HMAC_SHA1_96_AES128), parameters: Some(&[0x00, 0x00, 0x10, 0x00]), deprecated: false },
            Self::AES256_CTS_HMAC_SHA1_96 => KerberosEncryptionTypeSpecification { number: 18, name: "aes256-cts-hmac-sha1-96", key_size: Some(32), seed_size: Some(32), block_size: Some(16), message_block_size: Some(1), confounder_size: Some(16), integrity_size: Some(12), checksum: Some(KerberosChecksumType::HMAC_SHA1_96_AES256), parameters: Some(&[0x00, 0x00, 0x10, 0x00]), deprecated: false },
            Self::AES128_CTS_HMAC_SHA256_128 => KerberosEncryptionTypeSpecification { number: 19, name: "aes128-cts-hmac-sha256-128", key_size: Some(16), seed_size: Some(16), block_size: Some(16), message_block_size: None, confounder_size: Some(16), integrity_size: Some(16), checksum: Some(KerberosChecksumType::HMAC_SHA256_128_AES128), parameters: Some(&[0x00, 0x00, 0x80, 0x00]), deprecated: false },
            Self::AES256_CTS_HMAC_SHA384_192 => KerberosEncryptionTypeSpecification { number: 20, name: "aes256-cts-hmac-sha384-192", key_size: Some(32), seed_size: Some(32), block_size: Some(16), message_block_size: None, confounder_size: Some(16), integrity_size: Some(24), checksum: Some(KerberosChecksumType::HMAC_SHA384_192_AES256), parameters: Some(&[0x00, 0x00, 0x80, 0x00]), deprecated: false },
            Self::RC4_HMAC => KerberosEncryptionTypeSpecification { number: 23, name: "rc4-hmac", key_size: Some(16), seed_size: None, block_size: None, message_block_size: None, confounder_size: Some(8), integrity_size: Some(16), checksum: Some(KerberosChecksumType::HMAC_MD5), parameters: None, deprecated: true },
            Self::RC4_HMAC_EXP => KerberosEncryptionTypeSpecification { number: 24, name: "rc4-hmac-exp", key_size: Some(16), seed_size: None, block_size: None, message_block_size: None, confounder_size: Some(8), integrity_size: Some(16), checksum: Some(KerberosChecksumType::HMAC_MD5), parameters: None, deprecated: true },
            Self::CAMELLIA128_CTS_CMAC => KerberosEncryptionTypeSpecification { number: 25, name: "camellia128-cts-cmac", key_size: Some(16), seed_size: Some(16), block_size: Some(16), message_block_size: None, confounder_size: Some(16), integrity_size: Some(16), checksum: Some(KerberosChecksumType::CMAC_CAMELLIA128), parameters: Some(&[0x00, 0x00, 0x80, 0x00]), deprecated: false },
            Self::CAMELLIA256_CTS_CMAC => KerberosEncryptionTypeSpecification { number: 26, name: "camellia256-cts-cmac", key_size: Some(32), seed_size: Some(32), block_size: Some(16), message_block_size: None, confounder_size: Some(16), integrity_size: Some(16), checksum: Some(KerberosChecksumType::CMAC_CAMELLIA256), parameters: Some(&[0x00, 0x00, 0x80, 0x00]), deprecated: false },
            Self::SUBKEY_KEYMATERIAL => KerberosEncryptionTypeSpecification { number: 65, name: "subkey-keymaterial", key_size: None, seed_size: None, block_size: None, message_block_size: None, confounder_size: None, integrity_size: None, checksum: None, parameters: None, deprecated: false },
        }
    }

    pub fn number(&self) -> i32 {
        self.specification().number
    }

    pub fn from_number(number: i32) -> Option<Self> {
        Self::ALL.iter().copied().find(|encryption| encryption.number() == number)
    }

    pub fn key_size(&self) -> Option<usize> {
        self.specification().key_size
    }

    pub fn seed_size(&self) -> Option<usize> {
        self.specification().seed_size
    }

    pub fn block_size(&self) -> Option<usize> {
        self.specification().block_size
    }

    pub fn message_block_size(&self) -> Option<usize> {
        self.specification().message_block_size
    }

    pub fn confounder_size(&self) -> Option<usize> {
        self.specification().confounder_size
    }

    pub fn integrity_size(&self) -> Option<usize> {
        self.specification().integrity_size
    }

    pub fn checksum(&self) -> Option<KerberosChecksumType> {
        self.specification().checksum
    }

    pub fn parameters(&self) -> Option<&'static [u8]> {
        self.specification().parameters
    }

    pub fn deprecated(&self) -> bool {
        self.specification().deprecated
    }

    pub fn as_str(&self) -> &'static str {
        self.specification().name
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|encryption| encryption.as_str() == name)
    }
}

impl fmt::Display for KerberosEncryptionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KerberosChecksumTypeSpecification {
    pub number: i32,
    pub name: &'static str,
    pub size: usize,
    pub keyed: bool,
    pub confounded: bool,
    pub deprecated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KerberosChecksumType {
    CRC32,
    RSA_MD4,
    RSA_MD4_DES,
    DES_MAC,
    DES_MAC_K,
    RSA_MD4_DES_K,
    RSA_MD5,
    RSA_MD5_DES,
    RSA_MD5_DES3,
    NIST_SHA,
    HMAC_SHA1_DES3_KD,
    HMAC_SHA1_DES3,
    SHA1,
    HMAC_SHA1_96_AES128,
    HMAC_SHA1_96_AES256,
    CMAC_CAMELLIA128,
    CMAC_CAMELLIA256,
    HMAC_SHA256_128_AES128,
    HMAC_SHA384_192_AES256,
    HMAC_MD5,
}

impl KerberosChecksumType {
    pub const ALL: [Self; 20] = [
        Self::CRC32,
        Self::RSA_MD4,
        Self::RSA_MD4_DES,
        Self::DES_MAC,
        Self::DES_MAC_K,
        Self::RSA_MD4_DES_K,
        Self::RSA_MD5,
        Self::RSA_MD5_DES,
        Self::RSA_MD5_DES3,
        Self::NIST_SHA,
        Self::HMAC_SHA1_DES3_KD,
        Self::HMAC_SHA1_DES3,
        Self::SHA1,
        Self::HMAC_SHA1_96_AES128,
        Self::HMAC_SHA1_96_AES256,
        Self::CMAC_CAMELLIA128,
        Self::CMAC_CAMELLIA256,
        Self::HMAC_SHA256_128_AES128,
        Self::HMAC_SHA384_192_AES256,
        Self::HMAC_MD5,
    ];

    pub fn specification(&self) -> KerberosChecksumTypeSpecification {
        match self {
            Self::CRC32 => KerberosChecksumTypeSpecification { number: 1, name: "CRC32", size: 4, keyed: false, confounded: false, deprecated: true },
            Self::RSA_MD4 => KerberosChecksumTypeSpecification { number: 2, name: "rsa-md4", size: 16, keyed: false, confounded: false, deprecated: true },
            Self::RSA_MD4_DES => KerberosChecksumTypeSpecification { number: 3, name: "rsa-md4-des", size: 24, keyed: true, confounded: true, deprecated: true },
            Self::DES_MAC => KerberosChecksumTypeSpecification { number: 4, name: "des-mac", size: 16, keyed: true, confounded: true, deprecated: true },
            Self::DES_MAC_K => KerberosChecksumTypeSpecification { number: 5, name: "des-mac-k", size: 8, keyed: true, confounded: false, deprecated: true },
            Self::RSA_MD4_DES_K => KerberosChecksumTypeSpecification { number: 6, name: "rsa-md4-des-k", size: 16, keyed: true, confounded: false, deprecated: true },
            Self::RSA_MD5 => KerberosChecksumTypeSpecification { number: 7, name: "rsa-md5", size: 16, keyed: false, confounded: false, deprecated: true },
            Self::RSA_MD5_DES => KerberosChecksumTypeSpecification { number: 8, name: "rsa-md5-des", size: 24, keyed: true, confounded: true, deprecated: true },
            Self::RSA_MD5_DES3 => KerberosChecksumTypeSpecification { number: 9, name: "rsa-md5-des3", size: 24, keyed: true, confounded: false, deprecated: true },
            Self::NIST_SHA => KerberosChecksumTypeSpecification { number: 10, name: "sha1", size: 20, keyed: false, confounded: false, deprecated: false },
            Self::HMAC_SHA1_DES3_KD => KerberosChecksumTypeSpecification { number: 12, name: "hmac-sha1-des3-kd", size: 20, keyed: true, confounded: false, deprecated: true },
            Self::HMAC_SHA1_DES3 => KerberosChecksumTypeSpecification { number: 13, name: "hmac-sha1-des3", size: 20, keyed: true, confounded: false, deprecated: true },
            Self::SHA1 => KerberosChecksumTypeSpecification { number: 14, name: "sha1", size: 20, keyed: false, confounded: false, deprecated: false },
            Self::HMAC_SHA1_96_AES128 => KerberosChecksumTypeSpecification { number: 15, name: "hmac-sha1-96-aes128", size: 12, keyed: true, confounded: false, deprecated: false },
            Self::HMAC_SHA1_96_AES256 => KerberosChecksumTypeSpecification { number: 16, name: "hmac-sha1-96-aes256", size: 12, keyed: true, confounded: false, deprecated: false },
            Self::CMAC_CAMELLIA128 => KerberosChecksumTypeSpecification { number: 17, name: "cmac-camellia128", size: 16, keyed: true, confounded: false, deprecated: false },
            Self::CMAC_CAMELLIA256 => KerberosChecksumTypeSpecification { number: 18, name: "cmac-camellia256", size: 16, keyed: true, confounded: false, deprecated: false },
            Self::HMAC_SHA256_128_AES128 => KerberosChecksumTypeSpecification { number: 19, name: "hmac-sha256-128-aes128", size: 16, keyed: true, confounded: false, deprecated: false },
            Self::HMAC_SHA384_192_AES256 => KerberosChecksumTypeSpecification { number: 20, name: "hmac-sha384-192-aes256", size: 24, keyed: true, confounded: false, deprecated: false },
            Self::HMAC_MD5 => KerberosChecksumTypeSpecification { number: -138, name: "hmac-md5", size: 16, keyed: true, confounded: false, deprecated: true },
        }
    }

    pub fn number(&self) -> i32 {
        self.specification().number
    }

    pub fn from_number(number: i32) -> Option<Self> {
        Self::ALL.iter().copied().find(|checksum| checksum.number() == number)
    }

    pub fn size(&self) -> usize {
        self.specification().size
    }

    pub fn keyed(&self) -> bool {
        self.specification().keyed
    }

    pub fn confounded(&self) -> bool {
        self.specification().confounded
    }

    pub fn deprecated(&self) -> bool {
        self.specification().deprecated
    }

    pub fn as_str(&self) -> &'static str {
        self.specification().name
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|checksum| checksum.as_str() == name)
    }
}

impl fmt::Display for KerberosChecksumType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct KerberosLimits {
    pub max_message_size: u32,
    pub max_datagram_size: u32,
    pub max_ticket_size: u32,
    pub max_principal_components: u8,
    pub max_encryption_type_count: u8,
    pub max_preauthentication_count: u8,

    pub max_connection_count: u64,
    pub max_credential_count: u32,
    pub max_retry_count: u8,

    pub clock_skew: f64,
    pub request_timeout: f64,
    pub read_timeout: f64,
    pub write_timeout: f64,
    pub ticket_lifetime: f64,
    pub renew_lifetime: f64,
}

impl Default for KerberosLimits {
    fn default() -> Self {
        Self {
            max_message_size: 64 * 1024,
            max_datagram_size: 1465,
            max_ticket_size: 64 * 1024,
            max_principal_components: 16,
            max_encryption_type_count: 32,
            max_preauthentication_count: 16,

            max_connection_count: 1024,
            max_credential_count: 4096,
            max_retry_count: 3,

            clock_skew: 300.0,
            request_timeout: 10.0,
            read_timeout: 30.0,
            write_timeout: 30.0,
            ticket_lifetime: 36000.0,
            renew_lifetime: 604800.0,
        }
    }
}

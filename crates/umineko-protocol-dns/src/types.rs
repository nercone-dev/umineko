use alloc::{string::String, vec::Vec};
use core::fmt;
use crate::errors::DNSError;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DNSName(Vec<String>);

impl DNSName {
    pub const MAXIMUM_LENGTH: usize = 255;
    pub const MAXIMUM_LABEL_LENGTH: usize = 63;

    pub fn root() -> Self {
        todo!()
    }

    pub fn parse(text: &str) -> Result<Self, DNSError> {
        todo!()
    }

    pub fn labels(&self) -> &[String] {
        todo!()
    }

    pub fn parent(&self) -> Option<Self> {
        todo!()
    }

    pub fn subdomain_of(&self, other: &Self) -> bool {
        todo!()
    }

    pub fn matches(&self, other: &Self) -> bool {
        todo!()
    }

    pub fn encode(&self) -> Result<Vec<u8>, DNSError> {
        todo!()
    }

    pub fn decode(data: &[u8], offset: usize) -> Result<(Self, usize), DNSError> {
        todo!()
    }
}

impl fmt::Display for DNSName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DNSType {
    A,
    NS,
    CNAME,
    SOA,
    PTR,
    MX,
    TXT,
    AAAA,
    SRV,
    SVCB,
    HTTPS,
    DS,
    RRSIG,
    NSEC,
    DNSKEY,
    NSEC3,
    CAA,
    ANY,
    Unknown(u16),
}

impl DNSType {
    pub fn number(&self) -> u16 {
        todo!()
    }

    pub fn from_number(number: u16) -> Self {
        todo!()
    }

    pub fn as_str(&self) -> &'static str {
        todo!()
    }

    pub fn from_name(name: &str) -> Option<Self> {
        todo!()
    }

    pub fn query_only(&self) -> bool {
        matches!(self, Self::ANY)
    }
}

impl fmt::Display for DNSType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DNSClass {
    IN,
    CH,
    HS,
    ANY,
    Unknown(u16),
}

impl DNSClass {
    pub fn number(&self) -> u16 {
        todo!()
    }

    pub fn from_number(number: u16) -> Self {
        todo!()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DNSOpcode {
    Query,
    Status,
    Notify,
    Update,
    Unknown(u8),
}

impl DNSOpcode {
    pub fn number(&self) -> u8 {
        todo!()
    }

    pub fn from_number(number: u8) -> Self {
        todo!()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DNSResponseCode {
    NoError,
    FormatError,
    ServerFailure,
    NameError,
    NotImplemented,
    Refused,
    BadSignature,
    BadKey,
    BadTime,
    Unknown(u16),
}

impl DNSResponseCode {
    pub fn number(&self) -> u16 {
        todo!()
    }

    pub fn from_number(number: u16) -> Self {
        todo!()
    }

    pub fn success(&self) -> bool {
        matches!(self, Self::NoError)
    }

    pub fn retryable(&self) -> bool {
        matches!(self, Self::ServerFailure | Self::Refused)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DNSQuestion {
    pub name: DNSName,
    pub kind: DNSType,
    pub class: DNSClass,
}

impl DNSQuestion {
    pub fn encode(&self) -> Result<Vec<u8>, DNSError> {
        todo!()
    }

    pub fn decode(data: &[u8], offset: usize) -> Result<(Self, usize), DNSError> {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DNSRecord {
    pub name: DNSName,
    pub kind: DNSType,
    pub class: DNSClass,
    pub lifetime: u32,
    pub data: Vec<u8>,
}

impl DNSRecord {
    pub fn encode(&self) -> Result<Vec<u8>, DNSError> {
        todo!()
    }

    pub fn decode(data: &[u8], offset: usize) -> Result<(Self, usize), DNSError> {
        todo!()
    }

    pub fn describe(&self) -> Result<String, DNSError> {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DNSMessage {
    pub id: u16,
    pub response: bool,
    pub opcode: DNSOpcode,
    pub authoritative: bool,
    pub truncated: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub authentic_data: bool,
    pub checking_disabled: bool,
    pub code: DNSResponseCode,

    pub questions: Vec<DNSQuestion>,
    pub answers: Vec<DNSRecord>,
    pub authorities: Vec<DNSRecord>,
    pub additionals: Vec<DNSRecord>,
}

impl DNSMessage {
    pub const HEADER_SIZE: usize = 12;
    pub const MAXIMUM_UDP_SIZE: usize = 512;

    pub fn query(id: u16, question: DNSQuestion) -> Self {
        todo!()
    }

    pub fn reply(&self, code: DNSResponseCode) -> Self {
        todo!()
    }

    pub fn matches(&self, query: &Self) -> bool {
        todo!()
    }

    pub fn options(&self) -> Option<&DNSRecord> {
        todo!()
    }

    pub fn encode(&self, limits: DNSLimits) -> Result<Vec<u8>, DNSError> {
        todo!()
    }

    pub fn decode(data: &[u8], limits: DNSLimits) -> Result<Self, DNSError> {
        todo!()
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DNSLimits {
    pub max_message_size: u16,
    pub max_udp_payload_size: u16,
    pub max_name_length: u8,
    pub max_record_count: u16,
    pub max_question_count: u8,

    pub max_alias_count: u8,
    pub max_delegation_count: u8,
    pub max_retry_count: u8,

    pub max_cache_count: u32,
    pub max_cache_lifetime: u32,
    pub min_cache_lifetime: u32,

    pub connect_timeout: f64,
    pub query_timeout: f64,
    pub read_timeout: f64,
    pub write_timeout: f64,
}

impl Default for DNSLimits {
    fn default() -> Self {
        Self {
            max_message_size: 65535,
            max_udp_payload_size: 1232,
            max_name_length: 255,
            max_record_count: 256,
            max_question_count: 1,

            max_alias_count: 8,
            max_delegation_count: 16,
            max_retry_count: 2,

            max_cache_count: 16 * 1024,
            max_cache_lifetime: 86400,
            min_cache_lifetime: 1,

            connect_timeout: 5.0,
            query_timeout: 5.0,
            read_timeout: 5.0,
            write_timeout: 5.0,
        }
    }
}

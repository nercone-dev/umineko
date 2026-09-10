use alloc::{string::String, vec::Vec};
use core::{fmt, str::FromStr};
use crate::errors::HTTPError;
use crate::helpers::compression::HTTPCompression;

use umineko_helpers::Bytes;
use umineko_protocol_tls::{TLSVersion, TLSGroup, TLSCipher};
#[cfg(feature = "http30")]
use umineko_protocol_quic::QUICVersion;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HTTPPort {
    UDS(String),
    TCP(u16),
    QUIC(u16),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HTTPVersion {
    V1_0,
    V1_1,
    V2_0,
    V3_0,
}

impl HTTPVersion {
    pub fn alpn(&self) -> &'static str {
        match self {
            Self::V1_0 => "http/1.0",
            Self::V1_1 => "http/1.1",
            Self::V2_0 => "h2",
            Self::V3_0 => "h3",
        }
    }

    pub fn from_alpn(alpn: &str) -> Option<Self> {
        match alpn {
            "http/1.0" => Some(Self::V1_0),
            "http/1.1" => Some(Self::V1_1),
            "h2" => Some(Self::V2_0),
            "h3" => Some(Self::V3_0),
            _ => None,
        }
    }

    pub fn major(&self) -> u8 {
        match self {
            Self::V1_0 | Self::V1_1 => 1,
            Self::V2_0 => 2,
            Self::V3_0 => 3,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::V1_0 => "HTTP/1.0",
            Self::V1_1 => "HTTP/1.1",
            Self::V2_0 => "HTTP/2.0",
            Self::V3_0 => "HTTP/3.0",
        }
    }
}

impl fmt::Display for HTTPVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for HTTPVersion {
    type Err = ();

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text {
            "HTTP/1.0" => Ok(Self::V1_0),
            "HTTP/1.1" => Ok(Self::V1_1),
            "HTTP/2.0" => Ok(Self::V2_0),
            "HTTP/3.0" => Ok(Self::V3_0),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HTTPMethod {
    GET,
    HEAD,
    POST,
    PUT,
    DELETE,
    CONNECT,
    OPTIONS,
    TRACE,
    PATCH,
}

impl HTTPMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::GET => "GET",
            Self::HEAD => "HEAD",
            Self::POST => "POST",
            Self::PUT => "PUT",
            Self::DELETE => "DELETE",
            Self::CONNECT => "CONNECT",
            Self::OPTIONS => "OPTIONS",
            Self::TRACE => "TRACE",
            Self::PATCH => "PATCH",
        }
    }

    pub fn safe(&self) -> bool {
        matches!(self, Self::GET | Self::HEAD | Self::OPTIONS | Self::TRACE)
    }

    pub fn idempotent(&self) -> bool {
        self.safe() || matches!(self, Self::PUT | Self::DELETE)
    }
}

impl fmt::Display for HTTPMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for HTTPMethod {
    type Err = ();

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text {
            "GET" => Ok(Self::GET),
            "HEAD" => Ok(Self::HEAD),
            "POST" => Ok(Self::POST),
            "PUT" => Ok(Self::PUT),
            "DELETE" => Ok(Self::DELETE),
            "CONNECT" => Ok(Self::CONNECT),
            "OPTIONS" => Ok(Self::OPTIONS),
            "TRACE" => Ok(Self::TRACE),
            "PATCH" => Ok(Self::PATCH),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HTTPRole {
    UserAgent,
    Origin,
    Proxy,
    Gateway,
    Tunnel,
}

impl HTTPRole {
    pub fn is_client(&self) -> bool {
        matches!(self, Self::UserAgent | Self::Proxy)
    }

    pub fn is_server(&self) -> bool {
        matches!(self, Self::Origin | Self::Gateway)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HTTPHeaderCase {
    Title,
    Lower,
}

impl HTTPHeaderCase {
    pub fn apply(&self, name: &str) -> String {
        todo!()
    }

    pub fn from_version(version: HTTPVersion) -> Self {
        match version {
            HTTPVersion::V1_0 | HTTPVersion::V1_1 => Self::Title,
            HTTPVersion::V2_0 => Self::Lower,
            HTTPVersion::V3_0 => Self::Lower,
        }
    }
}

#[derive(Debug, Clone)]
pub struct HTTPHeader {
    name: String,
    value: String,
}

impl HTTPHeader {
    pub fn new(name: &str, value: &str) -> Self {
        todo!()
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn value(&self) -> &str {
        &self.value
    }

    pub fn matches(&self, name: &str) -> bool {
        todo!()
    }

    pub fn encode(&self, case: HTTPHeaderCase) -> String {
        todo!()
    }

    pub fn decode(line: &str) -> Result<Self, HTTPError> {
        todo!()
    }
}

#[derive(Debug, Clone)]
pub struct HTTPHeaders(Vec<HTTPHeader>);

impl HTTPHeaders {
    pub fn new() -> Self {
        todo!()
    }

    pub fn set(&mut self, name: &str, value: &str) {
        todo!()
    }

    pub fn insert(&mut self, name: &str, value: &str) {
        todo!()
    }

    pub fn remove(&mut self, name: &str) {
        todo!()
    }

    pub fn get(&self, name: &str) -> Option<String> {
        todo!()
    }

    pub fn get_all(&self, name: &str) -> Option<Vec<String>> {
        todo!()
    }

    pub fn contains(&self, name: &str) -> bool {
        todo!()
    }

    pub fn iter(&self) -> core::slice::Iter<'_, HTTPHeader> {
        self.0.iter()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn encode(&self, case: HTTPHeaderCase) -> Result<Vec<u8>, HTTPError> {
        todo!()
    }

    pub fn decode(data: &[u8], limits: HTTPLimits) -> Result<Self, HTTPError> {
        todo!()
    }
}

impl Default for HTTPHeaders {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HTTPBody {
    Data(Bytes),
    Text(String),
    File(String),
}

impl HTTPBody {
    pub fn len(&self) -> Option<usize> {
        match self {
            Self::Data(data) => Some(data.len()),
            Self::Text(text) => Some(text.len()),
            Self::File(_) => None,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == Some(0)
    }

    pub fn into_inline(self) -> Result<Bytes, String> {
        match self {
            Self::Data(data) => Ok(data),
            Self::Text(text) => Ok(Bytes::from(text.into_bytes())),
            Self::File(path) => Err(path),
        }
    }

    pub fn inline(&self) -> Option<Bytes> {
        match self {
            Self::Data(data) => Some(data.clone()),
            Self::Text(text) => Some(Bytes::copy_from_slice(text.as_bytes())),
            Self::File(_) => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HTTPStreamID(pub u64);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HTTPConnectionID(pub Bytes);

#[derive(Debug, Clone)]
pub struct HTTPMessage {
    pub version: Option<HTTPVersion>,

    pub body: Option<HTTPBody>,

    pub headers: Option<HTTPHeaders>,
    pub trailers: Option<HTTPHeaders>,

    pub method: Option<HTTPMethod>,
    pub target: Option<String>,
    pub status_code: Option<u16>,

    pub compression: Option<HTTPCompression>,

    pub secure: bool,
    pub early_data: bool,

    pub stream_id: Option<HTTPStreamID>,
    pub connection_id: Option<HTTPConnectionID>,

    pub tls: bool,
    pub tls_version: Option<TLSVersion>,
    pub tls_group: Option<TLSGroup>,
    pub tls_cipher: Option<TLSCipher>,

    pub quic: bool,
    #[cfg(feature = "http30")]
    pub quic_version: Option<QUICVersion>,
}

impl HTTPMessage {
    pub fn empty() -> Self {
        Self {
            version: None,
            body: None,
            headers: None,
            trailers: None,
            method: None,
            target: None,
            status_code: None,
            compression: None,
            secure: false,
            early_data: false,
            stream_id: None,
            connection_id: None,
            tls: false,
            tls_version: None,
            tls_group: None,
            tls_cipher: None,
            quic: false,
            #[cfg(feature = "http30")]
            quic_version: None,
        }
    }

    pub fn request(method: HTTPMethod, target: &str) -> Self {
        Self { method: Some(method), target: Some(String::from(target)), ..Self::empty() }
    }

    pub fn response(status_code: u16) -> Self {
        Self { status_code: Some(status_code), ..Self::empty() }
    }

    pub fn is_request(&self) -> bool {
        self.method.is_some()
    }

    pub fn is_response(&self) -> bool {
        self.status_code.is_some()
    }

    pub fn compress(&mut self, accepted: Option<Vec<HTTPCompression>>) -> Result<(), HTTPError> {
        todo!()
    }

    pub fn decompress(&mut self, max: u64) -> Result<(), HTTPError> {
        todo!()
    }

    pub fn encode(&self, version: HTTPVersion) -> Result<Vec<u8>, HTTPError> {
        todo!()
    }

    pub fn decode(data: &[u8], version: HTTPVersion, role: HTTPRole, limits: HTTPLimits) -> Result<Self, HTTPError> {
        todo!()
    }

    pub fn body_allowed(&self) -> bool {
        todo!()
    }

    pub fn validate(&self, limits: HTTPLimits) -> Result<(), HTTPError> {
        todo!()
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HTTPLimits {
    pub max_message_size:              u64,
    pub max_message_body_size:         u64,
    pub max_message_startline_size:    u32,
    pub max_message_header_size:       u64,
    pub max_message_header_count:      u16,

    pub max_connection_count:       u64,
    pub max_connection_buffer_size: u64,

    pub max_messages_per_connection: u64,

    pub handshake_timeout: f64,
    pub read_timeout:      f64,
    pub write_timeout:     f64,
    pub receive_timeout:   f64,
    pub send_timeout:      f64,
}

impl Default for HTTPLimits {
    fn default() -> Self {
        Self {
            max_message_size: 64 * 1024 * 1024,
            max_message_body_size: 64 * 1024 * 1024,
            max_message_startline_size: 256 * 1024 * 1024,
            max_message_header_size: 8 * 1024,
            max_message_header_count: 1024,

            max_connection_count: 100,
            max_connection_buffer_size: 128,

            max_messages_per_connection: 16 * 1024,

            handshake_timeout: 10.0,
            read_timeout: 30.0,
            write_timeout: 30.0,
            receive_timeout: 300.0,
            send_timeout: 1800.0,
        }
    }
}

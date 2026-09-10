use alloc::{string::String, vec::Vec};
use core::{fmt, str::FromStr};
use crate::errors::URLError;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum URLScheme {
    HTTP,
    HTTPS,
    WS,
    WSS,
    FTP,
    FTPS,
    SSH,
    SFTP,
    SMTP,
    SMTPS,
    IMAP,
    IMAPS,
    POP3,
    POP3S,
    DNS,
    MQTT,
    COAP,
    File,
    Data,
    Unknown(String),
}

impl URLScheme {
    pub fn as_str(&self) -> &str {
        todo!()
    }

    pub fn default_port(&self) -> Option<u16> {
        todo!()
    }

    pub fn secure(&self) -> bool {
        todo!()
    }

    pub fn from_name(name: &str) -> Self {
        todo!()
    }
}

impl fmt::Display for URLScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct URLUserInfo {
    pub username: String,
    pub password: Option<String>,
}

impl URLUserInfo {
    pub fn parse(text: &str) -> Result<Self, URLError> {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum URLHost {
    Domain(String),
    IPv4([u8; 4]),
    IPv6([u16; 8]),
}

impl URLHost {
    pub fn parse(text: &str) -> Result<Self, URLError> {
        todo!()
    }

        pub fn ascii(&self) -> Result<String, URLError> {
        todo!()
    }
}

impl fmt::Display for URLHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct URLPath(Vec<String>);

impl URLPath {
    pub fn new() -> Self {
        todo!()
    }

    pub fn parse(text: &str) -> Result<Self, URLError> {
        todo!()
    }

    pub fn segments(&self) -> &[String] {
        todo!()
    }

    pub fn push(&mut self, segment: &str) {
        todo!()
    }

        pub fn normalize(&self) -> Self {
        todo!()
    }
}

impl Default for URLPath {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for URLPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct URLQuery(Vec<(String, String)>);

impl URLQuery {
    pub fn new() -> Self {
        todo!()
    }

    pub fn parse(text: &str) -> Result<Self, URLError> {
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

    pub fn get(&self, name: &str) -> Option<&str> {
        todo!()
    }

    pub fn get_all(&self, name: &str) -> Option<Vec<&str>> {
        todo!()
    }

    pub fn contains(&self, name: &str) -> bool {
        todo!()
    }
}

impl Default for URLQuery {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for URLQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct URL {
    pub scheme: URLScheme,
    pub userinfo: Option<URLUserInfo>,
    pub host: Option<URLHost>,
    pub port: Option<u16>,
    pub path: URLPath,
    pub query: Option<URLQuery>,
    pub fragment: Option<String>,
}

impl URL {
    pub fn parse(text: &str) -> Result<Self, URLError> {
        todo!()
    }

        pub fn resolve(&self, reference: &str) -> Result<Self, URLError> {
        todo!()
    }

        pub fn effective_port(&self) -> Option<u16> {
        todo!()
    }

        pub fn authority(&self) -> Option<String> {
        todo!()
    }

        pub fn target(&self) -> String {
        todo!()
    }

        pub fn normalize(&self) -> Self {
        todo!()
    }
}

impl fmt::Display for URL {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl FromStr for URL {
    type Err = URLError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

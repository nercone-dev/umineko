use alloc::{string::String, vec::Vec};
use crate::errors::URLError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum URLEncoding {
    UserInfo,
    Host,
    Path,
    Query,
    Fragment,
}

impl URLEncoding {
    pub fn unreserved(&self, byte: u8) -> bool {
        todo!()
    }

    pub fn encode(&self, text: &str) -> String {
        todo!()
    }

    pub fn decode(&self, text: &str) -> Result<Vec<u8>, URLError> {
        todo!()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Punycode;

impl Punycode {
    pub const PREFIX: &'static str = "xn--";

    pub fn encode(label: &str) -> Result<String, URLError> {
        todo!()
    }

    pub fn decode(label: &str) -> Result<String, URLError> {
        todo!()
    }
}

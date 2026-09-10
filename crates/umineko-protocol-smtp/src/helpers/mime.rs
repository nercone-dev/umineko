use alloc::{string::String, vec::Vec};
use crate::errors::SMTPError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MIMEEncoding {
    SevenBit,
    EightBit,
    Binary,
    QuotedPrintable,
    Base64,
}

impl MIMEEncoding {
    pub fn as_str(&self) -> &'static str {
        todo!()
    }

    pub fn from_name(name: &str) -> Option<Self> {
        todo!()
    }

    pub fn encode(&self, data: &[u8]) -> Result<Vec<u8>, SMTPError> {
        todo!()
    }

    pub fn decode(&self, data: &[u8]) -> Result<Vec<u8>, SMTPError> {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MIMEPart {
    pub content_type: String,
    pub encoding: MIMEEncoding,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub parts: Vec<MIMEPart>,
}

impl MIMEPart {
    pub fn multipart(&self) -> bool {
        todo!()
    }

    pub fn encode(&self) -> Result<Vec<u8>, SMTPError> {
        todo!()
    }

    pub fn decode(data: &[u8]) -> Result<Self, SMTPError> {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MIMEMessage {
    pub headers: Vec<(String, String)>,
    pub root: MIMEPart,
}

impl MIMEMessage {
    pub fn header(&self, name: &str) -> Option<&str> {
        todo!()
    }

    pub fn set_header(&mut self, name: &str, value: &str) {
        todo!()
    }

    pub fn encode(&self) -> Result<Vec<u8>, SMTPError> {
        todo!()
    }

    pub fn decode(data: &[u8]) -> Result<Self, SMTPError> {
        todo!()
    }

    pub fn stuff(data: &[u8]) -> Vec<u8> {
        todo!()
    }

    pub fn unstuff(data: &[u8]) -> Vec<u8> {
        todo!()
    }
}

use alloc::{string::String, vec::Vec};
use crate::errors::BaseError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Base64Alphabet {
    Standard,
    URL,
}

impl Base64Alphabet {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Standard => "RFC 4648",
            Self::URL => "RFC 4648 URL and filename safe",
        }
    }

    pub fn symbol(&self, value: u8) -> Option<u8> {
        todo!()
    }

    pub fn value(&self, symbol: u8) -> Option<u8> {
        todo!()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Base64 {
    pub alphabet: Base64Alphabet,
    pub padding: bool,
}

impl Default for Base64 {
    fn default() -> Self {
        Self { alphabet: Base64Alphabet::Standard, padding: true }
    }
}

impl Base64 {
    pub fn encode(&self, data: &[u8]) -> String {
        todo!()
    }

    pub fn decode(&self, text: &str) -> Result<Vec<u8>, BaseError> {
        todo!()
    }

        pub fn encoded_len(&self, length: usize) -> usize {
        todo!()
    }

        pub fn decoded_len(&self, length: usize) -> usize {
        todo!()
    }
}

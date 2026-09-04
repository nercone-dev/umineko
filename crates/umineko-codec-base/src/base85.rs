use alloc::{string::String, vec::Vec};
use crate::errors::BaseError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Base85Alphabet {
    ASCII85,
    Z85,
    RFC1924,
}

impl Base85Alphabet {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ASCII85 => "Adobe ASCII85",
            Self::Z85 => "ZeroMQ Z85",
            Self::RFC1924 => "RFC 1924",
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
pub struct Base85 {
    pub alphabet: Base85Alphabet,
    pub padding: bool,
}

impl Default for Base85 {
    fn default() -> Self {
        Self { alphabet: Base85Alphabet::ASCII85, padding: true }
    }
}

impl Base85 {
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

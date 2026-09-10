use alloc::{string::String, vec::Vec};
use crate::errors::BaseError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Base32Alphabet {
    Standard,
    ExtendedHex,
    Crockford,
}

impl Base32Alphabet {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Standard => "RFC 4648",
            Self::ExtendedHex => "RFC 4648 extended hex",
            Self::Crockford => "Crockford",
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
pub struct Base32 {
    pub alphabet: Base32Alphabet,
    pub padding: bool,
}

impl Default for Base32 {
    fn default() -> Self {
        Self { alphabet: Base32Alphabet::Standard, padding: true }
    }
}

impl Base32 {
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

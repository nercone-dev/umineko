use alloc::{string::String, vec::Vec};
use crate::errors::BaseError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Base58Alphabet {
    Bitcoin,
    Ripple,
    Flickr,
}

impl Base58Alphabet {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Bitcoin => "Bitcoin",
            Self::Ripple => "Ripple",
            Self::Flickr => "Flickr",
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
pub struct Base58 {
    pub alphabet: Base58Alphabet,
    pub padding: bool,
}

impl Default for Base58 {
    fn default() -> Self {
        Self { alphabet: Base58Alphabet::Bitcoin, padding: true }
    }
}

impl Base58 {
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

use alloc::{string::String, vec::Vec};
use crate::errors::BaseError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Base16 {
    pub uppercase: bool,
}

impl Default for Base16 {
    fn default() -> Self {
        Self { uppercase: false }
    }
}

impl Base16 {
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

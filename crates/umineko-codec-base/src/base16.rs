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
    pub const LOWERCASE: &'static [u8; 16] = b"0123456789abcdef";
    pub const UPPERCASE: &'static [u8; 16] = b"0123456789ABCDEF";

    pub fn symbol(&self, value: u8) -> Option<u8> {
        let alphabet = match self.uppercase {
            true => Self::UPPERCASE,
            false => Self::LOWERCASE,
        };
        alphabet.get(value as usize).copied()
    }

    /// The value of every symbol, holding `NONE` for the bytes the alphabet leaves out.
    pub const VALUES: [u8; 256] = Self::values();
    /// The entry the value table holds for a byte no symbol names.
    pub const NONE: u8 = 0xFF;

    pub const fn values() -> [u8; 256] {
        let mut values = [Self::NONE; 256];
        let mut index = 0;
        while index < Self::LOWERCASE.len() {
            values[Self::LOWERCASE[index] as usize] = index as u8;
            values[Self::UPPERCASE[index] as usize] = index as u8;
            index += 1;
        }
        values
    }

    pub fn value(&self, symbol: u8) -> Option<u8> {
        match Self::VALUES[symbol as usize] {
            Self::NONE => None,
            value => Some(value),
        }
    }

    pub fn encode(&self, data: &[u8]) -> String {
        let mut text = String::with_capacity(self.encoded_len(data.len()));
        for byte in data {
            text.push(self.symbol(byte >> 4).unwrap_or(b'0') as char);
            text.push(self.symbol(byte & 0x0F).unwrap_or(b'0') as char);
        }
        text
    }

    pub fn decode(&self, text: &str) -> Result<Vec<u8>, BaseError> {
        let symbols = text.as_bytes();
        if symbols.len() % 2 != 0 {
            return Err(BaseError::Length);
        }
        let mut data = Vec::with_capacity(self.decoded_len(symbols.len()));
        for pair in symbols.chunks_exact(2) {
            let high = self.value(pair[0]).ok_or(BaseError::Alphabet)?;
            let low = self.value(pair[1]).ok_or(BaseError::Alphabet)?;
            data.push((high << 4) | low);
        }
        Ok(data)
    }

    /// The exact number of symbols produced for `length` bytes.
    pub fn encoded_len(&self, length: usize) -> usize {
        length * 2
    }

    /// The exact number of bytes produced for `length` symbols.
    pub fn decoded_len(&self, length: usize) -> usize {
        length / 2
    }
}

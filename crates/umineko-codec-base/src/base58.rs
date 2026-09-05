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

    pub fn table(&self) -> &'static [u8; 58] {
        match self {
            Self::Bitcoin => b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
            Self::Ripple => b"rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz",
            Self::Flickr => b"123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ",
        }
    }

    pub fn symbol(&self, value: u8) -> Option<u8> {
        self.table().get(value as usize).copied()
    }

    pub fn value(&self, symbol: u8) -> Option<u8> {
        self.table().iter().position(|entry| *entry == symbol).map(|value| value as u8)
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
    pub const RADIX: u32 = 58;

    pub fn encode(&self, data: &[u8]) -> String {
        let zeros = match self.padding {
            true => data.iter().take_while(|byte| **byte == 0).count(),
            false => 0,
        };
        let mut digits: Vec<u8> = Vec::with_capacity(self.encoded_len(data.len()));
        for byte in &data[zeros..] {
            let mut carry = *byte as u32;
            for digit in digits.iter_mut() {
                carry += (*digit as u32) << 8;
                *digit = (carry % Self::RADIX) as u8;
                carry /= Self::RADIX;
            }
            while carry != 0 {
                digits.push((carry % Self::RADIX) as u8);
                carry /= Self::RADIX;
            }
        }
        let mut text = String::with_capacity(zeros + digits.len());
        for _ in 0..zeros {
            text.push(self.alphabet.symbol(0).unwrap_or(b'1') as char);
        }
        for digit in digits.iter().rev() {
            text.push(self.alphabet.symbol(*digit).unwrap_or(b'1') as char);
        }
        text
    }

    pub fn decode(&self, text: &str) -> Result<Vec<u8>, BaseError> {
        let symbols = text.as_bytes();
        let zero = self.alphabet.symbol(0).ok_or(BaseError::Alphabet)?;
        let zeros = match self.padding {
            true => symbols.iter().take_while(|symbol| **symbol == zero).count(),
            false => 0,
        };
        let mut bytes: Vec<u8> = Vec::with_capacity(self.decoded_len(symbols.len()));
        for symbol in &symbols[zeros..] {
            let mut carry = self.alphabet.value(*symbol).ok_or(BaseError::Alphabet)? as u32;
            for byte in bytes.iter_mut() {
                carry += (*byte as u32) * Self::RADIX;
                *byte = carry as u8;
                carry >>= 8;
            }
            while carry != 0 {
                bytes.push(carry as u8);
                carry >>= 8;
            }
        }
        let mut data = Vec::with_capacity(zeros + bytes.len());
        data.resize(zeros, 0);
        data.extend(bytes.iter().rev());
        Ok(data)
    }

    /// The largest number of symbols produced for `length` bytes; the exact count depends on the value.
    pub fn encoded_len(&self, length: usize) -> usize {
        length * 138 / 100 + 1
    }

    /// The largest number of bytes produced for `length` symbols; the exact count depends on the value.
    pub fn decoded_len(&self, length: usize) -> usize {
        length * 733 / 1000 + 1
    }
}

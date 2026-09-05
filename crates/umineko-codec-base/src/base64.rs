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

    /// The value of every symbol, holding `NONE` for the bytes an alphabet leaves out.
    pub const STANDARD_VALUES: [u8; 256] = Self::Standard.values();
    pub const URL_VALUES: [u8; 256] = Self::URL.values();
    /// The entry a value table holds for a byte no symbol names.
    pub const NONE: u8 = 0xFF;

    pub const fn table(&self) -> &'static [u8; 64] {
        match self {
            Self::Standard => b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
            Self::URL => b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
        }
    }

    pub const fn values(&self) -> [u8; 256] {
        let table = self.table();
        let mut values = [Self::NONE; 256];
        let mut index = 0;
        while index < table.len() {
            values[table[index] as usize] = index as u8;
            index += 1;
        }
        values
    }

    /// The value table this alphabet reads its symbols through.
    pub fn table_values(&self) -> &'static [u8; 256] {
        match self {
            Self::Standard => &Self::STANDARD_VALUES,
            Self::URL => &Self::URL_VALUES,
        }
    }

    pub fn symbol(&self, value: u8) -> Option<u8> {
        self.table().get(value as usize).copied()
    }

    pub fn value(&self, symbol: u8) -> Option<u8> {
        match self.table_values()[symbol as usize] {
            Self::NONE => None,
            value => Some(value),
        }
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
    pub const PADDING: u8 = b'=';
    pub const GROUP: usize = 3;
    pub const SYMBOLS: usize = 4;

    /// The number of symbols carrying data for a final group of `bytes` bytes.
    pub fn symbols(bytes: usize) -> usize {
        match bytes {
            0 => 0,
            bytes => bytes + 1,
        }
    }

    /// The number of whole bytes carried by a final group of `symbols` symbols.
    pub fn bytes(symbols: usize) -> usize {
        symbols * 6 / 8
    }

    pub fn encode(&self, data: &[u8]) -> String {
        let table = self.alphabet.table();
        let mut text = String::with_capacity(self.encoded_len(data.len()));
        let mut groups = data.chunks_exact(Self::GROUP);
        for group in &mut groups {
            let value = u32::from_be_bytes([0, group[0], group[1], group[2]]);
            for index in 0..Self::SYMBOLS {
                text.push(table[(value >> (18 - index * 6)) as usize & 0x3F] as char);
            }
        }
        let group = groups.remainder();
        if !group.is_empty() {
            let mut buffer = [0; Self::GROUP];
            buffer[..group.len()].copy_from_slice(group);
            let value = u32::from_be_bytes([0, buffer[0], buffer[1], buffer[2]]);
            let symbols = Self::symbols(group.len());
            for index in 0..Self::SYMBOLS {
                match index < symbols {
                    true => text.push(table[(value >> (18 - index * 6)) as usize & 0x3F] as char),
                    false if self.padding => text.push(Self::PADDING as char),
                    false => {}
                }
            }
        }
        text
    }

    pub fn decode(&self, text: &str) -> Result<Vec<u8>, BaseError> {
        let symbols = self.strip(text.as_bytes())?;
        let values = self.alphabet.table_values();
        let mut data = Vec::with_capacity(Self::bytes(symbols.len()));
        let mut groups = symbols.chunks_exact(Self::SYMBOLS);
        for group in &mut groups {
            let mut value = 0u32;
            for symbol in group {
                match values[*symbol as usize] {
                    Base64Alphabet::NONE => return Err(BaseError::Alphabet),
                    entry => value = (value << 6) | entry as u32,
                }
            }
            data.extend_from_slice(&value.to_be_bytes()[1..]);
        }
        let group = groups.remainder();
        if !group.is_empty() {
            if Self::symbols(Self::bytes(group.len())) != group.len() {
                return Err(BaseError::Length);
            }
            let mut value = 0u32;
            for symbol in group {
                value = (value << 6) | self.alphabet.value(*symbol).ok_or(BaseError::Alphabet)? as u32;
            }
            value <<= 6 * (Self::SYMBOLS - group.len());
            let buffer = value.to_be_bytes();
            data.extend_from_slice(&buffer[1..1 + Self::bytes(group.len())]);
        }
        Ok(data)
    }

    pub fn strip<'a>(&self, symbols: &'a [u8]) -> Result<&'a [u8], BaseError> {
        match self.padding {
            false => Ok(symbols),
            true if symbols.len() % Self::SYMBOLS != 0 => Err(BaseError::Padding),
            true => {
                let padding = symbols.iter().rev().take_while(|symbol| **symbol == Self::PADDING).count();
                let stripped = &symbols[..symbols.len() - padding];
                match padding < Self::GROUP && Self::symbols(Self::bytes(stripped.len() % Self::SYMBOLS)) == stripped.len() % Self::SYMBOLS {
                    true => Ok(stripped),
                    false => Err(BaseError::Padding),
                }
            }
        }
    }

    /// The exact number of symbols produced for `length` bytes.
    pub fn encoded_len(&self, length: usize) -> usize {
        match self.padding {
            true => length.div_ceil(Self::GROUP) * Self::SYMBOLS,
            false => length / Self::GROUP * Self::SYMBOLS + Self::symbols(length % Self::GROUP),
        }
    }

    /// The largest number of bytes carried by `length` symbols.
    pub fn decoded_len(&self, length: usize) -> usize {
        Self::bytes(length)
    }
}

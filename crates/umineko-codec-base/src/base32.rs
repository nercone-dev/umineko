use alloc::borrow::Cow;
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

    pub const fn table(&self) -> &'static [u8; 32] {
        match self {
            Self::Standard => b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
            Self::ExtendedHex => b"0123456789ABCDEFGHIJKLMNOPQRSTUV",
            Self::Crockford => b"0123456789ABCDEFGHJKMNPQRSTVWXYZ",
        }
    }

    pub fn symbol(&self, value: u8) -> Option<u8> {
        self.table().get(value as usize).copied()
    }

    /// The value of every symbol, holding `NONE` for the bytes an alphabet leaves out.
    pub const STANDARD_VALUES: [u8; 256] = Self::Standard.values();
    pub const EXTENDED_HEX_VALUES: [u8; 256] = Self::ExtendedHex.values();
    pub const CROCKFORD_VALUES: [u8; 256] = Self::Crockford.values();
    /// The entry a value table holds for a byte no symbol names.
    pub const NONE: u8 = 0xFF;

    pub const fn values(&self) -> [u8; 256] {
        let table = self.table();
        let mut values = [Self::NONE; 256];
        let mut index = 0;
        while index < table.len() {
            values[table[index] as usize] = index as u8;
            index += 1;
        }
        match self {
            Self::Crockford => {
                let mut index = 0;
                while index < table.len() {
                    values[table[index].to_ascii_lowercase() as usize] = index as u8;
                    index += 1;
                }
                (values[b'I' as usize], values[b'i' as usize], values[b'L' as usize], values[b'l' as usize]) = (1, 1, 1, 1);
                (values[b'O' as usize], values[b'o' as usize]) = (0, 0);
                values
            }
            _ => values,
        }
    }

    /// The value table this alphabet reads its symbols through.
    pub fn table_values(&self) -> &'static [u8; 256] {
        match self {
            Self::Standard => &Self::STANDARD_VALUES,
            Self::ExtendedHex => &Self::EXTENDED_HEX_VALUES,
            Self::Crockford => &Self::CROCKFORD_VALUES,
        }
    }

    pub fn value(&self, symbol: u8) -> Option<u8> {
        match self.table_values()[symbol as usize] {
            Self::NONE => None,
            value => Some(value),
        }
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
    pub const PADDING: u8 = b'=';
    pub const GROUP: usize = 5;
    pub const SYMBOLS: usize = 8;

    /// The number of symbols carrying data for a final group of `bytes` bytes.
    pub fn symbols(bytes: usize) -> usize {
        (bytes * 8).div_ceil(5)
    }

    /// The number of whole bytes carried by a final group of `symbols` symbols.
    pub fn bytes(symbols: usize) -> usize {
        symbols * 5 / 8
    }

    pub fn encode(&self, data: &[u8]) -> String {
        let mut text = String::with_capacity(self.encoded_len(data.len()));
        for group in data.chunks(Self::GROUP) {
            let mut buffer = [0; Self::GROUP];
            buffer[..group.len()].copy_from_slice(group);
            let value = u64::from_be_bytes([0, 0, 0, buffer[0], buffer[1], buffer[2], buffer[3], buffer[4]]);
            let symbols = Self::symbols(group.len());
            for index in 0..Self::SYMBOLS {
                match index < symbols {
                    true => text.push(self.alphabet.symbol((value >> (35 - index * 5)) as u8 & 0x1F).unwrap_or(Self::PADDING) as char),
                    false if self.padding => text.push(Self::PADDING as char),
                    false => {}
                }
            }
        }
        text
    }

    pub fn decode(&self, text: &str) -> Result<Vec<u8>, BaseError> {
        let normalized = self.normalize(text);
        let symbols = self.strip(&normalized)?;
        let mut data = Vec::with_capacity(Self::bytes(symbols.len()));
        for group in symbols.chunks(Self::SYMBOLS) {
            if Self::symbols(Self::bytes(group.len())) != group.len() {
                return Err(BaseError::Length);
            }
            let mut value = 0u64;
            for symbol in group {
                value = (value << 5) | self.alphabet.value(*symbol).ok_or(BaseError::Alphabet)? as u64;
            }
            value <<= 5 * (Self::SYMBOLS - group.len());
            let buffer = value.to_be_bytes();
            data.extend_from_slice(&buffer[3..3 + Self::bytes(group.len())]);
        }
        Ok(data)
    }

    /// Drops the separators the alphabet allows inside encoded text.
    pub fn normalize<'a>(&self, text: &'a str) -> Cow<'a, [u8]> {
        match self.alphabet {
            Base32Alphabet::Crockford => Cow::Owned(text.bytes().filter(|symbol| *symbol != b'-').collect()),
            _ => Cow::Borrowed(text.as_bytes()),
        }
    }

    pub fn strip<'a>(&self, symbols: &'a [u8]) -> Result<&'a [u8], BaseError> {
        match self.padding {
            false => Ok(symbols),
            true if symbols.len() % Self::SYMBOLS != 0 => Err(BaseError::Padding),
            true => {
                let padding = symbols.iter().rev().take_while(|symbol| **symbol == Self::PADDING).count();
                let stripped = &symbols[..symbols.len() - padding];
                match padding < Self::SYMBOLS && Self::symbols(Self::bytes(stripped.len() % Self::SYMBOLS)) == stripped.len() % Self::SYMBOLS {
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

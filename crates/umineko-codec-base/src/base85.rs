use alloc::{string::String, vec::Vec};
use crate::errors::BaseError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Base85Alphabet {
    ASCII85,
    Z85,
    RFC1924,
}

impl Base85Alphabet {
    /// The ASCII85 shorthand for a group of four zero bytes.
    pub const ZERO: u8 = b'z';

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ASCII85 => "Adobe ASCII85",
            Self::Z85 => "ZeroMQ Z85",
            Self::RFC1924 => "RFC 1924",
        }
    }

    pub const fn table(&self) -> &'static [u8; 85] {
        match self {
            Self::ASCII85 => b"!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstu",
            Self::Z85 => b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#",
            Self::RFC1924 => b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~",
        }
    }

    /// Whether a group of four zero bytes may be written as the single shorthand symbol.
    pub fn shorthand(&self) -> bool {
        matches!(self, Self::ASCII85)
    }

    /// Whether the whole input is one big-endian integer rather than a run of four byte groups.
    pub fn integer(&self) -> bool {
        matches!(self, Self::RFC1924)
    }

    pub fn symbol(&self, value: u8) -> Option<u8> {
        self.table().get(value as usize).copied()
    }

    /// The value of every symbol, holding `NONE` for the bytes an alphabet leaves out.
    pub const ASCII85_VALUES: [u8; 256] = Self::ASCII85.values();
    pub const Z85_VALUES: [u8; 256] = Self::Z85.values();
    pub const RFC1924_VALUES: [u8; 256] = Self::RFC1924.values();
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
        values
    }

    /// The value table this alphabet reads its symbols through.
    pub fn table_values(&self) -> &'static [u8; 256] {
        match self {
            Self::ASCII85 => &Self::ASCII85_VALUES,
            Self::Z85 => &Self::Z85_VALUES,
            Self::RFC1924 => &Self::RFC1924_VALUES,
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
pub struct Base85 {
    pub alphabet: Base85Alphabet,
    /// Whether a partial final group is encoded as one symbol per byte plus one, so the exact
    /// length round-trips. When disabled the final group is padded out to four bytes and the
    /// encoded text always holds whole groups, as ZeroMQ Z85 requires.
    pub padding: bool,
}

impl Default for Base85 {
    fn default() -> Self {
        Self { alphabet: Base85Alphabet::ASCII85, padding: true }
    }
}

impl Base85 {
    pub const RADIX: u32 = 85;
    pub const GROUP: usize = 4;
    pub const SYMBOLS: usize = 5;

    pub fn encode(&self, data: &[u8]) -> String {
        match self.alphabet.integer() {
            true => self.encode_integer(data),
            false => self.encode_groups(data),
        }
    }

    pub fn decode(&self, text: &str) -> Result<Vec<u8>, BaseError> {
        match self.alphabet.integer() {
            true => self.decode_integer(text),
            false => self.decode_groups(text),
        }
    }

    pub fn encode_groups(&self, data: &[u8]) -> String {
        let mut text = String::with_capacity(self.encoded_len(data.len()));
        for group in data.chunks(Self::GROUP) {
            let mut buffer = [0; Self::GROUP];
            buffer[..group.len()].copy_from_slice(group);
            let mut value = u32::from_be_bytes(buffer);
            if value == 0 && group.len() == Self::GROUP && self.alphabet.shorthand() {
                text.push(Base85Alphabet::ZERO as char);
                continue;
            }
            let mut symbols = [0; Self::SYMBOLS];
            for symbol in symbols.iter_mut().rev() {
                *symbol = self.alphabet.symbol((value % Self::RADIX) as u8).unwrap_or(0);
                value /= Self::RADIX;
            }
            let length = match self.padding {
                true => group.len() + 1,
                false => Self::SYMBOLS,
            };
            for symbol in &symbols[..length] {
                text.push(*symbol as char);
            }
        }
        text
    }

    pub fn decode_groups(&self, text: &str) -> Result<Vec<u8>, BaseError> {
        let mut data = Vec::with_capacity(self.decoded_len(text.len()));
        let mut group = [0u8; Self::SYMBOLS];
        let mut length = 0;
        for symbol in text.bytes() {
            if symbol == Base85Alphabet::ZERO && self.alphabet.shorthand() {
                match length {
                    0 => data.extend_from_slice(&[0; Self::GROUP]),
                    _ => return Err(BaseError::Alphabet),
                }
                continue;
            }
            group[length] = self.alphabet.value(symbol).ok_or(BaseError::Alphabet)?;
            length += 1;
            if length == Self::SYMBOLS {
                data.extend_from_slice(&Self::bytes(&group)?);
                length = 0;
            }
        }
        match length {
            0 => Ok(data),
            1 => Err(BaseError::Length),
            _ if !self.padding => Err(BaseError::Length),
            _ => {
                group[length..].fill((Self::RADIX - 1) as u8);
                let bytes = Self::bytes(&group)?;
                data.extend_from_slice(&bytes[..length - 1]);
                Ok(data)
            }
        }
    }

    pub fn encode_integer(&self, data: &[u8]) -> String {
        let mut digits: Vec<u8> = Vec::with_capacity(Self::digits(data.len()));
        for byte in data {
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
        let mut text = String::with_capacity(Self::digits(data.len()));
        for index in (0..Self::digits(data.len())).rev() {
            text.push(self.alphabet.symbol(digits.get(index).copied().unwrap_or(0)).unwrap_or(0) as char);
        }
        text
    }

    pub fn decode_integer(&self, text: &str) -> Result<Vec<u8>, BaseError> {
        let symbols = text.as_bytes();
        let mut bytes: Vec<u8> = Vec::with_capacity(Self::octets(symbols.len()));
        for symbol in symbols {
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
        match bytes.len() > Self::octets(symbols.len()) {
            true => Err(BaseError::Length),
            false => {
                let mut data = Vec::with_capacity(Self::octets(symbols.len()));
                data.resize(Self::octets(symbols.len()) - bytes.len(), 0);
                data.extend(bytes.iter().rev());
                Ok(data)
            }
        }
    }

    /// The number of base-85 digits an integer of `bytes` bytes needs; `log2(85)` is `64094 / 10000`.
    pub fn digits(bytes: usize) -> usize {
        (bytes * 80000).div_ceil(64094)
    }

    /// The number of bytes an integer of `digits` base-85 digits carries.
    pub fn octets(digits: usize) -> usize {
        digits * 64094 / 80000
    }

    /// Folds five base-85 digits into the four bytes they carry.
    pub fn bytes(digits: &[u8; Self::SYMBOLS]) -> Result<[u8; Self::GROUP], BaseError> {
        let mut value = 0u32;
        for digit in digits {
            value = value.checked_mul(Self::RADIX).and_then(|value| value.checked_add(*digit as u32)).ok_or(BaseError::Length)?;
        }
        Ok(value.to_be_bytes())
    }

    /// The largest number of symbols produced for `length` bytes; shorthand groups make it shorter.
    pub fn encoded_len(&self, length: usize) -> usize {
        match (self.alphabet.integer(), self.padding) {
            (true, _) => Self::digits(length),
            (false, true) => length / Self::GROUP * Self::SYMBOLS + (length % Self::GROUP) + usize::from(length % Self::GROUP != 0),
            (false, false) => length.div_ceil(Self::GROUP) * Self::SYMBOLS,
        }
    }

    /// The largest number of bytes produced for `length` symbols; shorthand groups make it longer.
    pub fn decoded_len(&self, length: usize) -> usize {
        match self.alphabet.integer() {
            true => Self::octets(length),
            false => length.div_ceil(Self::SYMBOLS) * Self::GROUP,
        }
    }
}

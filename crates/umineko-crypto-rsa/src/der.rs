use alloc::vec::Vec;
use crate::errors::RSAError;

/// The distinguished encoding rules, as far as the key formats of PKCS #1 need them.
pub struct DER;

impl DER {
    pub const INTEGER: u8 = 0x02;
    pub const SEQUENCE: u8 = 0x30;

    pub fn length(value: usize) -> Vec<u8> {
        if value < 0x80 {
            return alloc::vec![value as u8];
        }
        let bytes = value.to_be_bytes();
        let start = bytes.iter().position(|byte| *byte != 0).unwrap_or(bytes.len() - 1);
        let mut length = alloc::vec![0x80 | (bytes.len() - start) as u8];
        length.extend_from_slice(&bytes[start..]);
        length
    }

    pub fn field(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut field = alloc::vec![tag];
        field.extend_from_slice(&Self::length(content.len()));
        field.extend_from_slice(content);
        field
    }

    /// An unsigned value as an integer, without leading zeroes and never mistaken for a negative one.
    pub fn integer(value: &[u8]) -> Vec<u8> {
        let start = value.iter().position(|byte| *byte != 0).unwrap_or(value.len());
        let mut content = Vec::with_capacity(value.len() + 1);
        if start == value.len() || value[start] & 0x80 != 0 {
            content.push(0);
        }
        content.extend_from_slice(&value[start..]);
        Self::field(Self::INTEGER, &content)
    }

    pub fn sequence(fields: &[Vec<u8>]) -> Vec<u8> {
        let mut content = Vec::new();
        for field in fields {
            content.extend_from_slice(field);
        }
        Self::field(Self::SEQUENCE, &content)
    }

    /// The tag, the contents and whatever follows the first field of `data`.
    pub fn parse(data: &[u8]) -> Result<(u8, &[u8], &[u8]), RSAError> {
        let (tag, rest) = data.split_first().ok_or(RSAError::Encoding)?;
        let (first, rest) = rest.split_first().ok_or(RSAError::Encoding)?;
        let (length, rest) = match first {
            first if *first < 0x80 => (*first as usize, rest),
            first => {
                let count = (first & 0x7F) as usize;
                if count == 0 || count > 8 || rest.len() < count {
                    return Err(RSAError::Encoding);
                }
                let mut length = 0usize;
                for byte in &rest[..count] {
                    length = length.checked_mul(256).and_then(|value| value.checked_add(*byte as usize)).ok_or(RSAError::Encoding)?;
                }
                (length, &rest[count..])
            }
        };
        match rest.len() >= length {
            true => Ok((*tag, &rest[..length], &rest[length..])),
            false => Err(RSAError::Encoding),
        }
    }

    pub fn open(data: &[u8], tag: u8) -> Result<(&[u8], &[u8]), RSAError> {
        let (found, content, rest) = Self::parse(data)?;
        match found == tag {
            true => Ok((content, rest)),
            false => Err(RSAError::Encoding),
        }
    }

    /// The magnitude of one integer field, with the sign byte of the encoding removed.
    pub fn value(data: &[u8]) -> Result<(Vec<u8>, &[u8]), RSAError> {
        let (content, rest) = Self::open(data, Self::INTEGER)?;
        match content.split_first() {
            None => Err(RSAError::Encoding),
            Some((0x00, tail)) => Ok((tail.to_vec(), rest)),
            Some((first, _)) if first & 0x80 != 0 => Err(RSAError::Encoding),
            Some(_) => Ok((content.to_vec(), rest)),
        }
    }
}

use alloc::vec::Vec;
use core::fmt;
use crate::errors::RC2Error;

use umineko_helpers::provider::{CipherProviderRequest, CipherProviders};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RC2Mode {
    ECB,
    CBC,
}

impl RC2Mode {
    pub fn padded(&self) -> bool {
        matches!(self, Self::ECB | Self::CBC)
    }

    pub fn nonce_size(&self) -> Option<usize> {
        todo!()
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ECB => "ECB",
            Self::CBC => "CBC",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RC2Variant {
    V40,
    V64,
    V128,
}

impl RC2Variant {
    pub fn effective_bits(&self) -> usize {
        match self {
            Self::V40 => 40,
            Self::V64 => 64,
            Self::V128 => 128,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::V40 => "RC2-40",
            Self::V64 => "RC2-64",
            Self::V128 => "RC2-128",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "RC2-40" => Some(Self::V40),
            "RC2-64" => Some(Self::V64),
            "RC2-128" => Some(Self::V128),
            _ => None,
        }
    }

    pub fn name(&self, mode: RC2Mode) -> &'static str {
        match (self, mode) {
            (Self::V40, RC2Mode::ECB) => "RC2-40-ECB",
            (Self::V40, RC2Mode::CBC) => "RC2-40-CBC",
            (Self::V64, RC2Mode::ECB) => "RC2-64-ECB",
            (Self::V64, RC2Mode::CBC) => "RC2-64-CBC",
            (Self::V128, RC2Mode::ECB) => "RC2-128-ECB",
            (Self::V128, RC2Mode::CBC) => "RC2-128-CBC",
        }
    }
}

impl fmt::Display for RC2Variant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RC2 {
    mode: RC2Mode,
    variant: RC2Variant,
    key: Vec<u8>,
    expanded: [u16; 64],
}

impl RC2 {
    pub const MINIMUM_KEY_SIZE: usize = 1;
    pub const MAXIMUM_KEY_SIZE: usize = 128;
    pub const BLOCK_SIZE: usize = 8;

    pub fn new(mode: RC2Mode, variant: RC2Variant, key: &[u8]) -> Result<Self, RC2Error> {
        if key.len() < Self::MINIMUM_KEY_SIZE || key.len() > Self::MAXIMUM_KEY_SIZE {
            return Err(RC2Error::Key);
        }
        Ok(Self { mode, variant, key: key.to_vec(), expanded: [0; 64] })
    }

    pub fn mode(&self) -> RC2Mode {
        self.mode
    }

    pub fn variant(&self) -> RC2Variant {
        self.variant
    }

    pub fn request<'a>(&'a self, nonce: &'a [u8]) -> CipherProviderRequest<'a> {
        CipherProviderRequest::new(self.variant.name(self.mode), &self.key).with_nonce(nonce).with_padding(self.mode.padded())
    }

    pub fn encrypt(&self, nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, RC2Error> {
        match CipherProviders::encrypt(&self.request(nonce), plaintext)? {
            Some(ciphertext) => Ok(ciphertext),
            None => todo!(),
        }
    }

    pub fn decrypt(&self, nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, RC2Error> {
        match CipherProviders::decrypt(&self.request(nonce), ciphertext)? {
            Some(plaintext) => Ok(plaintext),
            None => todo!(),
        }
    }

    pub fn encrypt_block(&self, block: &mut [u8; 8]) {
        let request = CipherProviderRequest::new(self.variant.name(RC2Mode::ECB), &self.key);
        match CipherProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.encrypt(&request, block)) {
            Some(output) if output.len() == block.len() => block.copy_from_slice(&output),
            _ => todo!(),
        }
    }

    pub fn decrypt_block(&self, block: &mut [u8; 8]) {
        let request = CipherProviderRequest::new(self.variant.name(RC2Mode::ECB), &self.key);
        match CipherProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.decrypt(&request, block)) {
            Some(output) if output.len() == block.len() => block.copy_from_slice(&output),
            _ => todo!(),
        }
    }
}

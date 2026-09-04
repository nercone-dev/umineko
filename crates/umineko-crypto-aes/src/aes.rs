use alloc::vec::Vec;
use core::fmt;
use crate::errors::AESError;

use umineko_helpers::provider::{CipherProviderRequest, CipherProviders};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AES {
    V128,
    V192,
    V256,
}

impl AES {
    pub const BLOCK_SIZE: usize = 16;

    pub fn key_size(&self) -> usize {
        match self {
            Self::V128 => 16,
            Self::V192 => 24,
            Self::V256 => 32,
        }
    }

    pub fn rounds(&self) -> usize {
        match self {
            Self::V128 => 10,
            Self::V192 => 12,
            Self::V256 => 14,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::V128 => "AES-128",
            Self::V192 => "AES-192",
            Self::V256 => "AES-256",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "AES-128" => Some(Self::V128),
            "AES-192" => Some(Self::V192),
            "AES-256" => Some(Self::V256),
            _ => None,
        }
    }

    pub fn name(&self, mode: AESMode) -> &'static str {
        match (self, mode) {
            (Self::V128, AESMode::ECB) => "AES-128-ECB",
            (Self::V128, AESMode::CBC) => "AES-128-CBC",
            (Self::V128, AESMode::CFB) => "AES-128-CFB",
            (Self::V128, AESMode::OFB) => "AES-128-OFB",
            (Self::V128, AESMode::CTR) => "AES-128-CTR",
            (Self::V128, AESMode::GCM) => "AES-128-GCM",
            (Self::V128, AESMode::CCM) => "AES-128-CCM",
            (Self::V192, AESMode::ECB) => "AES-192-ECB",
            (Self::V192, AESMode::CBC) => "AES-192-CBC",
            (Self::V192, AESMode::CFB) => "AES-192-CFB",
            (Self::V192, AESMode::OFB) => "AES-192-OFB",
            (Self::V192, AESMode::CTR) => "AES-192-CTR",
            (Self::V192, AESMode::GCM) => "AES-192-GCM",
            (Self::V192, AESMode::CCM) => "AES-192-CCM",
            (Self::V256, AESMode::ECB) => "AES-256-ECB",
            (Self::V256, AESMode::CBC) => "AES-256-CBC",
            (Self::V256, AESMode::CFB) => "AES-256-CFB",
            (Self::V256, AESMode::OFB) => "AES-256-OFB",
            (Self::V256, AESMode::CTR) => "AES-256-CTR",
            (Self::V256, AESMode::GCM) => "AES-256-GCM",
            (Self::V256, AESMode::CCM) => "AES-256-CCM",
        }
    }
}

impl fmt::Display for AES {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AESMode {
    ECB,
    CBC,
    CFB,
    OFB,
    CTR,
    GCM,
    CCM,
}

impl AESMode {
        pub fn authenticated(&self) -> bool {
        matches!(self, Self::GCM | Self::CCM)
    }

        pub fn padded(&self) -> bool {
        matches!(self, Self::ECB | Self::CBC)
    }

    pub fn nonce_size(&self) -> Option<usize> {
        todo!()
    }

    pub fn tag_size(&self) -> Option<usize> {
        todo!()
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ECB => "ECB",
            Self::CBC => "CBC",
            Self::CFB => "CFB",
            Self::OFB => "OFB",
            Self::CTR => "CTR",
            Self::GCM => "GCM",
            Self::CCM => "CCM",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AES128 {
    mode: AESMode,
    key: [u8; 16],
    round_keys: [[u8; 16]; 15],
}

impl AES128 {
    pub const VARIANT: AES = AES::V128;
    pub const KEY_SIZE: usize = 16;
    pub const BLOCK_SIZE: usize = 16;

    pub fn new(mode: AESMode, key: &[u8; 16]) -> Self {
        Self { mode, key: *key, round_keys: [[0; 16]; 15] }
    }

    pub fn mode(&self) -> AESMode {
        self.mode
    }

    pub fn request<'a>(&'a self, nonce: &'a [u8], associated: &'a [u8]) -> CipherProviderRequest<'a> {
        CipherProviderRequest::new(Self::VARIANT.name(self.mode), &self.key).with_nonce(nonce).with_associated(associated).with_padding(self.mode.padded())
    }

    pub fn encrypt(&self, nonce: &[u8], associated: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, AESError> {
        match CipherProviders::encrypt(&self.request(nonce, associated), plaintext)? {
            Some(ciphertext) => Ok(ciphertext),
            None => todo!(),
        }
    }

    pub fn decrypt(&self, nonce: &[u8], associated: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, AESError> {
        match CipherProviders::decrypt(&self.request(nonce, associated), ciphertext)? {
            Some(plaintext) => Ok(plaintext),
            None => todo!(),
        }
    }

    pub fn encrypt_block(&self, block: &mut [u8; 16]) {
        let request = CipherProviderRequest::new(Self::VARIANT.name(AESMode::ECB), &self.key);
        match CipherProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.encrypt(&request, block)) {
            Some(output) if output.len() == block.len() => block.copy_from_slice(&output),
            _ => todo!(),
        }
    }

    pub fn decrypt_block(&self, block: &mut [u8; 16]) {
        let request = CipherProviderRequest::new(Self::VARIANT.name(AESMode::ECB), &self.key);
        match CipherProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.decrypt(&request, block)) {
            Some(output) if output.len() == block.len() => block.copy_from_slice(&output),
            _ => todo!(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AES192 {
    mode: AESMode,
    key: [u8; 24],
    round_keys: [[u8; 16]; 15],
}

impl AES192 {
    pub const VARIANT: AES = AES::V192;
    pub const KEY_SIZE: usize = 24;
    pub const BLOCK_SIZE: usize = 16;

    pub fn new(mode: AESMode, key: &[u8; 24]) -> Self {
        Self { mode, key: *key, round_keys: [[0; 16]; 15] }
    }

    pub fn mode(&self) -> AESMode {
        self.mode
    }

    pub fn request<'a>(&'a self, nonce: &'a [u8], associated: &'a [u8]) -> CipherProviderRequest<'a> {
        CipherProviderRequest::new(Self::VARIANT.name(self.mode), &self.key).with_nonce(nonce).with_associated(associated).with_padding(self.mode.padded())
    }

    pub fn encrypt(&self, nonce: &[u8], associated: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, AESError> {
        match CipherProviders::encrypt(&self.request(nonce, associated), plaintext)? {
            Some(ciphertext) => Ok(ciphertext),
            None => todo!(),
        }
    }

    pub fn decrypt(&self, nonce: &[u8], associated: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, AESError> {
        match CipherProviders::decrypt(&self.request(nonce, associated), ciphertext)? {
            Some(plaintext) => Ok(plaintext),
            None => todo!(),
        }
    }

    pub fn encrypt_block(&self, block: &mut [u8; 16]) {
        let request = CipherProviderRequest::new(Self::VARIANT.name(AESMode::ECB), &self.key);
        match CipherProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.encrypt(&request, block)) {
            Some(output) if output.len() == block.len() => block.copy_from_slice(&output),
            _ => todo!(),
        }
    }

    pub fn decrypt_block(&self, block: &mut [u8; 16]) {
        let request = CipherProviderRequest::new(Self::VARIANT.name(AESMode::ECB), &self.key);
        match CipherProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.decrypt(&request, block)) {
            Some(output) if output.len() == block.len() => block.copy_from_slice(&output),
            _ => todo!(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AES256 {
    mode: AESMode,
    key: [u8; 32],
    round_keys: [[u8; 16]; 15],
}

impl AES256 {
    pub const VARIANT: AES = AES::V256;
    pub const KEY_SIZE: usize = 32;
    pub const BLOCK_SIZE: usize = 16;

    pub fn new(mode: AESMode, key: &[u8; 32]) -> Self {
        Self { mode, key: *key, round_keys: [[0; 16]; 15] }
    }

    pub fn mode(&self) -> AESMode {
        self.mode
    }

    pub fn request<'a>(&'a self, nonce: &'a [u8], associated: &'a [u8]) -> CipherProviderRequest<'a> {
        CipherProviderRequest::new(Self::VARIANT.name(self.mode), &self.key).with_nonce(nonce).with_associated(associated).with_padding(self.mode.padded())
    }

    pub fn encrypt(&self, nonce: &[u8], associated: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, AESError> {
        match CipherProviders::encrypt(&self.request(nonce, associated), plaintext)? {
            Some(ciphertext) => Ok(ciphertext),
            None => todo!(),
        }
    }

    pub fn decrypt(&self, nonce: &[u8], associated: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, AESError> {
        match CipherProviders::decrypt(&self.request(nonce, associated), ciphertext)? {
            Some(plaintext) => Ok(plaintext),
            None => todo!(),
        }
    }

    pub fn encrypt_block(&self, block: &mut [u8; 16]) {
        let request = CipherProviderRequest::new(Self::VARIANT.name(AESMode::ECB), &self.key);
        match CipherProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.encrypt(&request, block)) {
            Some(output) if output.len() == block.len() => block.copy_from_slice(&output),
            _ => todo!(),
        }
    }

    pub fn decrypt_block(&self, block: &mut [u8; 16]) {
        let request = CipherProviderRequest::new(Self::VARIANT.name(AESMode::ECB), &self.key);
        match CipherProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.decrypt(&request, block)) {
            Some(output) if output.len() == block.len() => block.copy_from_slice(&output),
            _ => todo!(),
        }
    }
}

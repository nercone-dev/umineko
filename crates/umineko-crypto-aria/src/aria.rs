use alloc::vec::Vec;
use core::fmt;
use crate::errors::ARIAError;

use umineko_helpers::provider::{CipherProviderRequest, CipherProviders};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ARIA {
    V128,
    V192,
    V256,
}

impl ARIA {
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
            Self::V128 => 12,
            Self::V192 => 14,
            Self::V256 => 16,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::V128 => "ARIA-128",
            Self::V192 => "ARIA-192",
            Self::V256 => "ARIA-256",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "ARIA-128" => Some(Self::V128),
            "ARIA-192" => Some(Self::V192),
            "ARIA-256" => Some(Self::V256),
            _ => None,
        }
    }

    pub fn name(&self, mode: ARIAMode) -> &'static str {
        match (self, mode) {
            (Self::V128, ARIAMode::ECB) => "ARIA-128-ECB",
            (Self::V128, ARIAMode::CBC) => "ARIA-128-CBC",
            (Self::V128, ARIAMode::CFB) => "ARIA-128-CFB",
            (Self::V128, ARIAMode::OFB) => "ARIA-128-OFB",
            (Self::V128, ARIAMode::CTR) => "ARIA-128-CTR",
            (Self::V128, ARIAMode::GCM) => "ARIA-128-GCM",
            (Self::V192, ARIAMode::ECB) => "ARIA-192-ECB",
            (Self::V192, ARIAMode::CBC) => "ARIA-192-CBC",
            (Self::V192, ARIAMode::CFB) => "ARIA-192-CFB",
            (Self::V192, ARIAMode::OFB) => "ARIA-192-OFB",
            (Self::V192, ARIAMode::CTR) => "ARIA-192-CTR",
            (Self::V192, ARIAMode::GCM) => "ARIA-192-GCM",
            (Self::V256, ARIAMode::ECB) => "ARIA-256-ECB",
            (Self::V256, ARIAMode::CBC) => "ARIA-256-CBC",
            (Self::V256, ARIAMode::CFB) => "ARIA-256-CFB",
            (Self::V256, ARIAMode::OFB) => "ARIA-256-OFB",
            (Self::V256, ARIAMode::CTR) => "ARIA-256-CTR",
            (Self::V256, ARIAMode::GCM) => "ARIA-256-GCM",
        }
    }
}

impl fmt::Display for ARIA {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ARIAMode {
    ECB,
    CBC,
    CFB,
    OFB,
    CTR,
    GCM,
}

impl ARIAMode {
    pub fn authenticated(&self) -> bool {
        matches!(self, Self::GCM)
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
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ARIA128 {
    mode: ARIAMode,
    key: [u8; 16],
    round_keys: [[u8; 16]; 17],
}

impl ARIA128 {
    pub const VARIANT: ARIA = ARIA::V128;
    pub const KEY_SIZE: usize = 16;
    pub const BLOCK_SIZE: usize = 16;

    pub fn new(mode: ARIAMode, key: &[u8; 16]) -> Self {
        Self { mode, key: *key, round_keys: [[0; 16]; 17] }
    }

    pub fn mode(&self) -> ARIAMode {
        self.mode
    }

    pub fn request<'a>(&'a self, nonce: &'a [u8], associated: &'a [u8]) -> CipherProviderRequest<'a> {
        CipherProviderRequest::new(Self::VARIANT.name(self.mode), &self.key).with_nonce(nonce).with_associated(associated).with_padding(self.mode.padded())
    }

    pub fn encrypt(&self, nonce: &[u8], associated: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, ARIAError> {
        match CipherProviders::encrypt(&self.request(nonce, associated), plaintext)? {
            Some(ciphertext) => Ok(ciphertext),
            None => todo!(),
        }
    }

    pub fn decrypt(&self, nonce: &[u8], associated: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, ARIAError> {
        match CipherProviders::decrypt(&self.request(nonce, associated), ciphertext)? {
            Some(plaintext) => Ok(plaintext),
            None => todo!(),
        }
    }

    pub fn encrypt_block(&self, block: &mut [u8; 16]) {
        let request = CipherProviderRequest::new(Self::VARIANT.name(ARIAMode::ECB), &self.key);
        match CipherProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.encrypt(&request, block)) {
            Some(output) if output.len() == block.len() => block.copy_from_slice(&output),
            _ => todo!(),
        }
    }

    pub fn decrypt_block(&self, block: &mut [u8; 16]) {
        let request = CipherProviderRequest::new(Self::VARIANT.name(ARIAMode::ECB), &self.key);
        match CipherProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.decrypt(&request, block)) {
            Some(output) if output.len() == block.len() => block.copy_from_slice(&output),
            _ => todo!(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ARIA192 {
    mode: ARIAMode,
    key: [u8; 24],
    round_keys: [[u8; 16]; 17],
}

impl ARIA192 {
    pub const VARIANT: ARIA = ARIA::V192;
    pub const KEY_SIZE: usize = 24;
    pub const BLOCK_SIZE: usize = 16;

    pub fn new(mode: ARIAMode, key: &[u8; 24]) -> Self {
        Self { mode, key: *key, round_keys: [[0; 16]; 17] }
    }

    pub fn mode(&self) -> ARIAMode {
        self.mode
    }

    pub fn request<'a>(&'a self, nonce: &'a [u8], associated: &'a [u8]) -> CipherProviderRequest<'a> {
        CipherProviderRequest::new(Self::VARIANT.name(self.mode), &self.key).with_nonce(nonce).with_associated(associated).with_padding(self.mode.padded())
    }

    pub fn encrypt(&self, nonce: &[u8], associated: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, ARIAError> {
        match CipherProviders::encrypt(&self.request(nonce, associated), plaintext)? {
            Some(ciphertext) => Ok(ciphertext),
            None => todo!(),
        }
    }

    pub fn decrypt(&self, nonce: &[u8], associated: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, ARIAError> {
        match CipherProviders::decrypt(&self.request(nonce, associated), ciphertext)? {
            Some(plaintext) => Ok(plaintext),
            None => todo!(),
        }
    }

    pub fn encrypt_block(&self, block: &mut [u8; 16]) {
        let request = CipherProviderRequest::new(Self::VARIANT.name(ARIAMode::ECB), &self.key);
        match CipherProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.encrypt(&request, block)) {
            Some(output) if output.len() == block.len() => block.copy_from_slice(&output),
            _ => todo!(),
        }
    }

    pub fn decrypt_block(&self, block: &mut [u8; 16]) {
        let request = CipherProviderRequest::new(Self::VARIANT.name(ARIAMode::ECB), &self.key);
        match CipherProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.decrypt(&request, block)) {
            Some(output) if output.len() == block.len() => block.copy_from_slice(&output),
            _ => todo!(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ARIA256 {
    mode: ARIAMode,
    key: [u8; 32],
    round_keys: [[u8; 16]; 17],
}

impl ARIA256 {
    pub const VARIANT: ARIA = ARIA::V256;
    pub const KEY_SIZE: usize = 32;
    pub const BLOCK_SIZE: usize = 16;

    pub fn new(mode: ARIAMode, key: &[u8; 32]) -> Self {
        Self { mode, key: *key, round_keys: [[0; 16]; 17] }
    }

    pub fn mode(&self) -> ARIAMode {
        self.mode
    }

    pub fn request<'a>(&'a self, nonce: &'a [u8], associated: &'a [u8]) -> CipherProviderRequest<'a> {
        CipherProviderRequest::new(Self::VARIANT.name(self.mode), &self.key).with_nonce(nonce).with_associated(associated).with_padding(self.mode.padded())
    }

    pub fn encrypt(&self, nonce: &[u8], associated: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, ARIAError> {
        match CipherProviders::encrypt(&self.request(nonce, associated), plaintext)? {
            Some(ciphertext) => Ok(ciphertext),
            None => todo!(),
        }
    }

    pub fn decrypt(&self, nonce: &[u8], associated: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, ARIAError> {
        match CipherProviders::decrypt(&self.request(nonce, associated), ciphertext)? {
            Some(plaintext) => Ok(plaintext),
            None => todo!(),
        }
    }

    pub fn encrypt_block(&self, block: &mut [u8; 16]) {
        let request = CipherProviderRequest::new(Self::VARIANT.name(ARIAMode::ECB), &self.key);
        match CipherProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.encrypt(&request, block)) {
            Some(output) if output.len() == block.len() => block.copy_from_slice(&output),
            _ => todo!(),
        }
    }

    pub fn decrypt_block(&self, block: &mut [u8; 16]) {
        let request = CipherProviderRequest::new(Self::VARIANT.name(ARIAMode::ECB), &self.key);
        match CipherProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.decrypt(&request, block)) {
            Some(output) if output.len() == block.len() => block.copy_from_slice(&output),
            _ => todo!(),
        }
    }
}

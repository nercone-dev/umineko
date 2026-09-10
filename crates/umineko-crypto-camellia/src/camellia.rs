use alloc::vec::Vec;
use core::fmt;
use crate::errors::CamelliaError;

use umineko_helpers::provider::{CipherProviderRequest, CipherProviders};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Camellia {
    V128,
    V192,
    V256,
}

impl Camellia {
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
            Self::V128 => 18,
            Self::V192 => 24,
            Self::V256 => 24,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::V128 => "Camellia-128",
            Self::V192 => "Camellia-192",
            Self::V256 => "Camellia-256",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "Camellia-128" => Some(Self::V128),
            "Camellia-192" => Some(Self::V192),
            "Camellia-256" => Some(Self::V256),
            _ => None,
        }
    }

    pub fn name(&self, mode: CamelliaMode) -> &'static str {
        match (self, mode) {
            (Self::V128, CamelliaMode::ECB) => "Camellia-128-ECB",
            (Self::V128, CamelliaMode::CBC) => "Camellia-128-CBC",
            (Self::V128, CamelliaMode::CFB) => "Camellia-128-CFB",
            (Self::V128, CamelliaMode::OFB) => "Camellia-128-OFB",
            (Self::V128, CamelliaMode::CTR) => "Camellia-128-CTR",
            (Self::V128, CamelliaMode::GCM) => "Camellia-128-GCM",
            (Self::V128, CamelliaMode::CCM) => "Camellia-128-CCM",
            (Self::V192, CamelliaMode::ECB) => "Camellia-192-ECB",
            (Self::V192, CamelliaMode::CBC) => "Camellia-192-CBC",
            (Self::V192, CamelliaMode::CFB) => "Camellia-192-CFB",
            (Self::V192, CamelliaMode::OFB) => "Camellia-192-OFB",
            (Self::V192, CamelliaMode::CTR) => "Camellia-192-CTR",
            (Self::V192, CamelliaMode::GCM) => "Camellia-192-GCM",
            (Self::V192, CamelliaMode::CCM) => "Camellia-192-CCM",
            (Self::V256, CamelliaMode::ECB) => "Camellia-256-ECB",
            (Self::V256, CamelliaMode::CBC) => "Camellia-256-CBC",
            (Self::V256, CamelliaMode::CFB) => "Camellia-256-CFB",
            (Self::V256, CamelliaMode::OFB) => "Camellia-256-OFB",
            (Self::V256, CamelliaMode::CTR) => "Camellia-256-CTR",
            (Self::V256, CamelliaMode::GCM) => "Camellia-256-GCM",
            (Self::V256, CamelliaMode::CCM) => "Camellia-256-CCM",
            (Self::V128, CamelliaMode::CBC_CS3) => "Camellia-128-CBC-CS3",
            (Self::V192, CamelliaMode::CBC_CS3) => "Camellia-192-CBC-CS3",
            (Self::V256, CamelliaMode::CBC_CS3) => "Camellia-256-CBC-CS3",
        }
    }
}

impl fmt::Display for Camellia {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CamelliaMode {
    ECB,
    CBC,
    CFB,
    OFB,
    CTR,
    GCM,
    CCM,
    CBC_CS3,
}

impl CamelliaMode {
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
            Self::CBC_CS3 => "CBC-CS3",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Camellia128 {
    mode: CamelliaMode,
    key: [u8; 16],
    subkeys: [u64; 34],
}

impl Camellia128 {
    pub const VARIANT: Camellia = Camellia::V128;
    pub const KEY_SIZE: usize = 16;
    pub const BLOCK_SIZE: usize = 16;

    pub fn new(mode: CamelliaMode, key: &[u8; 16]) -> Self {
        Self { mode, key: *key, subkeys: [0; 34] }
    }

    pub fn mode(&self) -> CamelliaMode {
        self.mode
    }

    pub fn request<'a>(&'a self, nonce: &'a [u8], associated: &'a [u8]) -> CipherProviderRequest<'a> {
        CipherProviderRequest::new(Self::VARIANT.name(self.mode), &self.key).with_nonce(nonce).with_associated(associated).with_padding(self.mode.padded())
    }

    pub fn encrypt(&self, nonce: &[u8], associated: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CamelliaError> {
        match CipherProviders::encrypt(&self.request(nonce, associated), plaintext)? {
            Some(ciphertext) => Ok(ciphertext),
            None => todo!(),
        }
    }

    pub fn decrypt(&self, nonce: &[u8], associated: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CamelliaError> {
        match CipherProviders::decrypt(&self.request(nonce, associated), ciphertext)? {
            Some(plaintext) => Ok(plaintext),
            None => todo!(),
        }
    }

    pub fn encrypt_block(&self, block: &mut [u8; 16]) {
        let request = CipherProviderRequest::new(Self::VARIANT.name(CamelliaMode::ECB), &self.key);
        match CipherProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.encrypt(&request, block)) {
            Some(output) if output.len() == block.len() => block.copy_from_slice(&output),
            _ => todo!(),
        }
    }

    pub fn decrypt_block(&self, block: &mut [u8; 16]) {
        let request = CipherProviderRequest::new(Self::VARIANT.name(CamelliaMode::ECB), &self.key);
        match CipherProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.decrypt(&request, block)) {
            Some(output) if output.len() == block.len() => block.copy_from_slice(&output),
            _ => todo!(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Camellia192 {
    mode: CamelliaMode,
    key: [u8; 24],
    subkeys: [u64; 34],
}

impl Camellia192 {
    pub const VARIANT: Camellia = Camellia::V192;
    pub const KEY_SIZE: usize = 24;
    pub const BLOCK_SIZE: usize = 16;

    pub fn new(mode: CamelliaMode, key: &[u8; 24]) -> Self {
        Self { mode, key: *key, subkeys: [0; 34] }
    }

    pub fn mode(&self) -> CamelliaMode {
        self.mode
    }

    pub fn request<'a>(&'a self, nonce: &'a [u8], associated: &'a [u8]) -> CipherProviderRequest<'a> {
        CipherProviderRequest::new(Self::VARIANT.name(self.mode), &self.key).with_nonce(nonce).with_associated(associated).with_padding(self.mode.padded())
    }

    pub fn encrypt(&self, nonce: &[u8], associated: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CamelliaError> {
        match CipherProviders::encrypt(&self.request(nonce, associated), plaintext)? {
            Some(ciphertext) => Ok(ciphertext),
            None => todo!(),
        }
    }

    pub fn decrypt(&self, nonce: &[u8], associated: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CamelliaError> {
        match CipherProviders::decrypt(&self.request(nonce, associated), ciphertext)? {
            Some(plaintext) => Ok(plaintext),
            None => todo!(),
        }
    }

    pub fn encrypt_block(&self, block: &mut [u8; 16]) {
        let request = CipherProviderRequest::new(Self::VARIANT.name(CamelliaMode::ECB), &self.key);
        match CipherProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.encrypt(&request, block)) {
            Some(output) if output.len() == block.len() => block.copy_from_slice(&output),
            _ => todo!(),
        }
    }

    pub fn decrypt_block(&self, block: &mut [u8; 16]) {
        let request = CipherProviderRequest::new(Self::VARIANT.name(CamelliaMode::ECB), &self.key);
        match CipherProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.decrypt(&request, block)) {
            Some(output) if output.len() == block.len() => block.copy_from_slice(&output),
            _ => todo!(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Camellia256 {
    mode: CamelliaMode,
    key: [u8; 32],
    subkeys: [u64; 34],
}

impl Camellia256 {
    pub const VARIANT: Camellia = Camellia::V256;
    pub const KEY_SIZE: usize = 32;
    pub const BLOCK_SIZE: usize = 16;

    pub fn new(mode: CamelliaMode, key: &[u8; 32]) -> Self {
        Self { mode, key: *key, subkeys: [0; 34] }
    }

    pub fn mode(&self) -> CamelliaMode {
        self.mode
    }

    pub fn request<'a>(&'a self, nonce: &'a [u8], associated: &'a [u8]) -> CipherProviderRequest<'a> {
        CipherProviderRequest::new(Self::VARIANT.name(self.mode), &self.key).with_nonce(nonce).with_associated(associated).with_padding(self.mode.padded())
    }

    pub fn encrypt(&self, nonce: &[u8], associated: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CamelliaError> {
        match CipherProviders::encrypt(&self.request(nonce, associated), plaintext)? {
            Some(ciphertext) => Ok(ciphertext),
            None => todo!(),
        }
    }

    pub fn decrypt(&self, nonce: &[u8], associated: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CamelliaError> {
        match CipherProviders::decrypt(&self.request(nonce, associated), ciphertext)? {
            Some(plaintext) => Ok(plaintext),
            None => todo!(),
        }
    }

    pub fn encrypt_block(&self, block: &mut [u8; 16]) {
        let request = CipherProviderRequest::new(Self::VARIANT.name(CamelliaMode::ECB), &self.key);
        match CipherProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.encrypt(&request, block)) {
            Some(output) if output.len() == block.len() => block.copy_from_slice(&output),
            _ => todo!(),
        }
    }

    pub fn decrypt_block(&self, block: &mut [u8; 16]) {
        let request = CipherProviderRequest::new(Self::VARIANT.name(CamelliaMode::ECB), &self.key);
        match CipherProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.decrypt(&request, block)) {
            Some(output) if output.len() == block.len() => block.copy_from_slice(&output),
            _ => todo!(),
        }
    }
}

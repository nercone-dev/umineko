use alloc::vec::Vec;
use crate::errors::DESError;

use umineko_helpers::provider::{CipherProviderRequest, CipherProviders};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DESMode {
    ECB,
    CBC,
    CFB,
    OFB,
    CTR,
}

impl DESMode {
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
            Self::CFB => "CFB",
            Self::OFB => "OFB",
            Self::CTR => "CTR",
        }
    }

    pub fn name(&self, triple: bool) -> &'static str {
        match (triple, self) {
            (false, Self::ECB) => "DES-ECB",
            (false, Self::CBC) => "DES-CBC",
            (false, Self::CFB) => "DES-CFB",
            (false, Self::OFB) => "DES-OFB",
            (false, Self::CTR) => "DES-CTR",
            (true, Self::ECB) => "3DES-ECB",
            (true, Self::CBC) => "3DES-CBC",
            (true, Self::CFB) => "3DES-CFB",
            (true, Self::OFB) => "3DES-OFB",
            (true, Self::CTR) => "3DES-CTR",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DES {
    mode: DESMode,
    key: [u8; 8],
    round_keys: [[u8; 6]; 16],
}

impl DES {
    pub const KEY_SIZE: usize = 8;
    pub const BLOCK_SIZE: usize = 8;

    pub fn new(mode: DESMode, key: &[u8; 8]) -> Self {
        Self { mode, key: *key, round_keys: [[0; 6]; 16] }
    }

    pub fn mode(&self) -> DESMode {
        self.mode
    }

    pub fn request<'a>(&'a self, nonce: &'a [u8]) -> CipherProviderRequest<'a> {
        CipherProviderRequest::new(self.mode.name(false), &self.key).with_nonce(nonce).with_padding(self.mode.padded())
    }

    pub fn encrypt(&self, nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, DESError> {
        match CipherProviders::encrypt(&self.request(nonce), plaintext)? {
            Some(ciphertext) => Ok(ciphertext),
            None => todo!(),
        }
    }

    pub fn decrypt(&self, nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, DESError> {
        match CipherProviders::decrypt(&self.request(nonce), ciphertext)? {
            Some(plaintext) => Ok(plaintext),
            None => todo!(),
        }
    }

    pub fn encrypt_block(&self, block: &mut [u8; 8]) {
        let request = CipherProviderRequest::new(DESMode::ECB.name(false), &self.key);
        match CipherProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.encrypt(&request, block)) {
            Some(output) if output.len() == block.len() => block.copy_from_slice(&output),
            _ => todo!(),
        }
    }

    pub fn decrypt_block(&self, block: &mut [u8; 8]) {
        let request = CipherProviderRequest::new(DESMode::ECB.name(false), &self.key);
        match CipherProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.decrypt(&request, block)) {
            Some(output) if output.len() == block.len() => block.copy_from_slice(&output),
            _ => todo!(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TripleDES {
    mode: DESMode,
    key: [u8; 24],
    ciphers: [DES; 3],
}

impl TripleDES {
    pub const KEY_SIZE: usize = 24;
    pub const BLOCK_SIZE: usize = 8;

    pub fn new(mode: DESMode, key: &[u8; 24]) -> Self {
        let mut parts = [[0; 8]; 3];
        for (part, chunk) in parts.iter_mut().zip(key.chunks(8)) {
            part.copy_from_slice(chunk);
        }
        Self { mode, key: *key, ciphers: [DES::new(DESMode::ECB, &parts[0]), DES::new(DESMode::ECB, &parts[1]), DES::new(DESMode::ECB, &parts[2])] }
    }

    pub fn mode(&self) -> DESMode {
        self.mode
    }

    pub fn request<'a>(&'a self, nonce: &'a [u8]) -> CipherProviderRequest<'a> {
        CipherProviderRequest::new(self.mode.name(true), &self.key).with_nonce(nonce).with_padding(self.mode.padded())
    }

    pub fn encrypt(&self, nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, DESError> {
        match CipherProviders::encrypt(&self.request(nonce), plaintext)? {
            Some(ciphertext) => Ok(ciphertext),
            None => todo!(),
        }
    }

    pub fn decrypt(&self, nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, DESError> {
        match CipherProviders::decrypt(&self.request(nonce), ciphertext)? {
            Some(plaintext) => Ok(plaintext),
            None => todo!(),
        }
    }

    pub fn encrypt_block(&self, block: &mut [u8; 8]) {
        let request = CipherProviderRequest::new(DESMode::ECB.name(true), &self.key);
        match CipherProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.encrypt(&request, block)) {
            Some(output) if output.len() == block.len() => block.copy_from_slice(&output),
            _ => todo!(),
        }
    }

    pub fn decrypt_block(&self, block: &mut [u8; 8]) {
        let request = CipherProviderRequest::new(DESMode::ECB.name(true), &self.key);
        match CipherProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.decrypt(&request, block)) {
            Some(output) if output.len() == block.len() => block.copy_from_slice(&output),
            _ => todo!(),
        }
    }
}

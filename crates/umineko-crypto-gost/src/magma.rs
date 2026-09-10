use alloc::vec::Vec;
use crate::errors::GOSTError;
use crate::gost::GOSTMode;

use umineko_helpers::provider::{CipherProviderRequest, CipherProviders, HashProviderRequest, HashProviders};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Magma {
    mode: GOSTMode,
    key: [u8; 32],
    section_size: Option<usize>,
    round_keys: [u32; 32],
}

impl Magma {
    pub const NAME: &'static str = "Magma";
    pub const MAC_NAME: &'static str = "OMAC-Magma";
    pub const KEY_SIZE: usize = 32;
    pub const BLOCK_SIZE: usize = 8;
    pub const MAC_SIZE: usize = 8;

    pub fn name(mode: GOSTMode) -> &'static str {
        match mode {
            GOSTMode::ECB => "Magma-ECB",
            GOSTMode::CBC => "Magma-CBC",
            GOSTMode::CFB => "Magma-CFB",
            GOSTMode::OFB => "Magma-OFB",
            GOSTMode::CTR => "Magma-CTR",
            GOSTMode::CTR_ACPKM => "Magma-CTR-ACPKM",
            GOSTMode::MGM => "Magma-MGM",
        }
    }

    pub fn nonce_size(mode: GOSTMode) -> Option<usize> {
        match mode {
            GOSTMode::ECB => None,
            GOSTMode::CBC | GOSTMode::CFB | GOSTMode::OFB | GOSTMode::MGM => Some(Self::BLOCK_SIZE),
            GOSTMode::CTR | GOSTMode::CTR_ACPKM => Some(Self::BLOCK_SIZE / 2),
        }
    }

    pub fn tag_size(mode: GOSTMode) -> Option<usize> {
        match mode {
            GOSTMode::MGM => Some(Self::BLOCK_SIZE),
            GOSTMode::ECB | GOSTMode::CBC | GOSTMode::CFB | GOSTMode::OFB | GOSTMode::CTR | GOSTMode::CTR_ACPKM => None,
        }
    }

    pub fn new(mode: GOSTMode, key: &[u8; 32]) -> Self {
        Self { mode, key: *key, section_size: None, round_keys: [0; 32] }
    }

    pub fn with_section_size(self, section_size: usize) -> Result<Self, GOSTError> {
        if section_size == 0 || section_size % Self::BLOCK_SIZE != 0 {
            return Err(GOSTError::Length);
        }
        Ok(Self { section_size: Some(section_size), ..self })
    }

    pub fn mode(&self) -> GOSTMode {
        self.mode
    }

    pub fn section_size(&self) -> Option<usize> {
        self.section_size
    }

    pub fn request<'a>(&'a self, nonce: &'a [u8], associated: &'a [u8]) -> CipherProviderRequest<'a> {
        CipherProviderRequest::new(Self::name(self.mode), &self.key).with_nonce(nonce).with_associated(associated).with_padding(self.mode.padded()).with_section_size(self.section_size)
    }

    pub fn encrypt(&self, nonce: &[u8], associated: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, GOSTError> {
        match CipherProviders::encrypt(&self.request(nonce, associated), plaintext)? {
            Some(ciphertext) => Ok(ciphertext),
            None => todo!(),
        }
    }

    pub fn decrypt(&self, nonce: &[u8], associated: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, GOSTError> {
        match CipherProviders::decrypt(&self.request(nonce, associated), ciphertext)? {
            Some(plaintext) => Ok(plaintext),
            None => todo!(),
        }
    }

    pub fn encrypt_block(&self, block: &mut [u8; 8]) {
        let request = CipherProviderRequest::new(Self::name(GOSTMode::ECB), &self.key);
        match CipherProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.encrypt(&request, block)) {
            Some(output) if output.len() == block.len() => block.copy_from_slice(&output),
            _ => todo!(),
        }
    }

    pub fn decrypt_block(&self, block: &mut [u8; 8]) {
        let request = CipherProviderRequest::new(Self::name(GOSTMode::ECB), &self.key);
        match CipherProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.decrypt(&request, block)) {
            Some(output) if output.len() == block.len() => block.copy_from_slice(&output),
            _ => todo!(),
        }
    }

    pub fn mac(&self, data: &[u8], tag: &mut [u8]) -> usize {
        match HashProviders::digest(&HashProviderRequest::new(Self::MAC_NAME).with_key(&self.key), data, tag) {
            Some(length) => length,
            None => todo!(),
        }
    }

    pub fn export_key(&self, mac: &Self, key: &[u8], nonce: &[u8]) -> Result<Vec<u8>, GOSTError> {
        todo!()
    }

    pub fn import_key(&self, mac: &Self, exported: &[u8], nonce: &[u8]) -> Result<Vec<u8>, GOSTError> {
        todo!()
    }
}

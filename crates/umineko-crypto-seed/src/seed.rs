use alloc::vec::Vec;
use crate::errors::SEEDError;

use umineko_helpers::provider::{CipherProviderRequest, CipherProviders};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SEEDMode {
    ECB,
    CBC,
    CFB,
    OFB,
    CTR,
}

impl SEEDMode {
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

    pub fn name(&self) -> &'static str {
        match self {
            Self::ECB => "SEED-ECB",
            Self::CBC => "SEED-CBC",
            Self::CFB => "SEED-CFB",
            Self::OFB => "SEED-OFB",
            Self::CTR => "SEED-CTR",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SEED {
    mode: SEEDMode,
    key: [u8; 16],
    round_keys: [u32; 32],
}

impl SEED {
    pub const KEY_SIZE: usize = 16;
    pub const BLOCK_SIZE: usize = 16;

    pub fn new(mode: SEEDMode, key: &[u8; 16]) -> Self {
        Self { mode, key: *key, round_keys: [0; 32] }
    }

    pub fn mode(&self) -> SEEDMode {
        self.mode
    }

    pub fn request<'a>(&'a self, nonce: &'a [u8]) -> CipherProviderRequest<'a> {
        CipherProviderRequest::new(self.mode.name(), &self.key).with_nonce(nonce).with_padding(self.mode.padded())
    }

    pub fn encrypt(&self, nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, SEEDError> {
        match CipherProviders::encrypt(&self.request(nonce), plaintext)? {
            Some(ciphertext) => Ok(ciphertext),
            None => todo!(),
        }
    }

    pub fn decrypt(&self, nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, SEEDError> {
        match CipherProviders::decrypt(&self.request(nonce), ciphertext)? {
            Some(plaintext) => Ok(plaintext),
            None => todo!(),
        }
    }

    pub fn encrypt_block(&self, block: &mut [u8; 16]) {
        let request = CipherProviderRequest::new(SEEDMode::ECB.name(), &self.key);
        match CipherProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.encrypt(&request, block)) {
            Some(output) if output.len() == block.len() => block.copy_from_slice(&output),
            _ => todo!(),
        }
    }

    pub fn decrypt_block(&self, block: &mut [u8; 16]) {
        let request = CipherProviderRequest::new(SEEDMode::ECB.name(), &self.key);
        match CipherProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.decrypt(&request, block)) {
            Some(output) if output.len() == block.len() => block.copy_from_slice(&output),
            _ => todo!(),
        }
    }
}

use alloc::vec::Vec;
use crate::errors::IDEAError;

use umineko_helpers::provider::{CipherProviderRequest, CipherProviders};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IDEAMode {
    ECB,
    CBC,
    CFB,
    OFB,
}

impl IDEAMode {
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
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::ECB => "IDEA-ECB",
            Self::CBC => "IDEA-CBC",
            Self::CFB => "IDEA-CFB",
            Self::OFB => "IDEA-OFB",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IDEA {
    mode: IDEAMode,
    key: [u8; 16],
    subkeys: [u16; 52],
}

impl IDEA {
    pub const KEY_SIZE: usize = 16;
    pub const BLOCK_SIZE: usize = 8;

    pub fn new(mode: IDEAMode, key: &[u8; 16]) -> Self {
        Self { mode, key: *key, subkeys: [0; 52] }
    }

    pub fn mode(&self) -> IDEAMode {
        self.mode
    }

    pub fn request<'a>(&'a self, nonce: &'a [u8]) -> CipherProviderRequest<'a> {
        CipherProviderRequest::new(self.mode.name(), &self.key).with_nonce(nonce).with_padding(self.mode.padded())
    }

    pub fn encrypt(&self, nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, IDEAError> {
        match CipherProviders::encrypt(&self.request(nonce), plaintext)? {
            Some(ciphertext) => Ok(ciphertext),
            None => todo!(),
        }
    }

    pub fn decrypt(&self, nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, IDEAError> {
        match CipherProviders::decrypt(&self.request(nonce), ciphertext)? {
            Some(plaintext) => Ok(plaintext),
            None => todo!(),
        }
    }

    pub fn encrypt_block(&self, block: &mut [u8; 8]) {
        let request = CipherProviderRequest::new(IDEAMode::ECB.name(), &self.key);
        match CipherProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.encrypt(&request, block)) {
            Some(output) if output.len() == block.len() => block.copy_from_slice(&output),
            _ => todo!(),
        }
    }

    pub fn decrypt_block(&self, block: &mut [u8; 8]) {
        let request = CipherProviderRequest::new(IDEAMode::ECB.name(), &self.key);
        match CipherProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.decrypt(&request, block)) {
            Some(output) if output.len() == block.len() => block.copy_from_slice(&output),
            _ => todo!(),
        }
    }
}

use alloc::vec::Vec;
use crate::errors::SM4Error;

use umineko_helpers::provider::{CipherProviderRequest, CipherProviders};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SM4Mode {
    ECB,
    CBC,
    CFB,
    OFB,
    CTR,
    GCM,
    CCM,
}

impl SM4Mode {
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

    pub fn name(&self) -> &'static str {
        match self {
            Self::ECB => "SM4-ECB",
            Self::CBC => "SM4-CBC",
            Self::CFB => "SM4-CFB",
            Self::OFB => "SM4-OFB",
            Self::CTR => "SM4-CTR",
            Self::GCM => "SM4-GCM",
            Self::CCM => "SM4-CCM",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SM4 {
    mode: SM4Mode,
    key: [u8; 16],
    round_keys: [u32; 32],
}

impl SM4 {
    pub const KEY_SIZE: usize = 16;
    pub const BLOCK_SIZE: usize = 16;

    pub fn new(mode: SM4Mode, key: &[u8; 16]) -> Self {
        Self { mode, key: *key, round_keys: [0; 32] }
    }

    pub fn mode(&self) -> SM4Mode {
        self.mode
    }

    pub fn request<'a>(&'a self, nonce: &'a [u8], associated: &'a [u8]) -> CipherProviderRequest<'a> {
        CipherProviderRequest::new(self.mode.name(), &self.key).with_nonce(nonce).with_associated(associated).with_padding(self.mode.padded())
    }

    pub fn encrypt(&self, nonce: &[u8], associated: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, SM4Error> {
        match CipherProviders::encrypt(&self.request(nonce, associated), plaintext)? {
            Some(ciphertext) => Ok(ciphertext),
            None => todo!(),
        }
    }

    pub fn decrypt(&self, nonce: &[u8], associated: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, SM4Error> {
        match CipherProviders::decrypt(&self.request(nonce, associated), ciphertext)? {
            Some(plaintext) => Ok(plaintext),
            None => todo!(),
        }
    }

    pub fn encrypt_block(&self, block: &mut [u8; 16]) {
        let request = CipherProviderRequest::new(SM4Mode::ECB.name(), &self.key);
        match CipherProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.encrypt(&request, block)) {
            Some(output) if output.len() == block.len() => block.copy_from_slice(&output),
            _ => todo!(),
        }
    }

    pub fn decrypt_block(&self, block: &mut [u8; 16]) {
        let request = CipherProviderRequest::new(SM4Mode::ECB.name(), &self.key);
        match CipherProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.decrypt(&request, block)) {
            Some(output) if output.len() == block.len() => block.copy_from_slice(&output),
            _ => todo!(),
        }
    }
}

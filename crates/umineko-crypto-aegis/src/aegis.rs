use alloc::vec::Vec;
use crate::errors::AEGISError;

use umineko_helpers::provider::{CipherProviderRequest, CipherProviders};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AEGIS128L {
    key: [u8; 16],
    tag_size: usize,
    state: [[u8; 16]; 8],
}

impl AEGIS128L {
    pub const NAME: &'static str = "AEGIS-128L";
    pub const KEY_SIZE: usize = 16;
    pub const NONCE_SIZE: usize = 16;
    pub const TAG_SIZES: [usize; 2] = [16, 32];

    pub fn new(key: &[u8; 16], tag_size: usize) -> Result<Self, AEGISError> {
        if !Self::TAG_SIZES.contains(&tag_size) {
            return Err(AEGISError::Tag);
        }
        Ok(Self { key: *key, tag_size, state: [[0; 16]; 8] })
    }

    pub fn tag_size(&self) -> usize {
        self.tag_size
    }

    pub fn request<'a>(&'a self, nonce: &'a [u8; 16], associated: &'a [u8]) -> CipherProviderRequest<'a> {
        CipherProviderRequest::new(Self::NAME, &self.key).with_nonce(nonce).with_associated(associated).with_tag_size(self.tag_size)
    }

    pub fn encrypt(&self, nonce: &[u8; 16], associated: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, AEGISError> {
        match CipherProviders::encrypt(&self.request(nonce, associated), plaintext)? {
            Some(ciphertext) => Ok(ciphertext),
            None => todo!(),
        }
    }

    pub fn decrypt(&self, nonce: &[u8; 16], associated: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, AEGISError> {
        match CipherProviders::decrypt(&self.request(nonce, associated), ciphertext)? {
            Some(plaintext) => Ok(plaintext),
            None => todo!(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AEGIS256 {
    key: [u8; 32],
    tag_size: usize,
    state: [[u8; 16]; 6],
}

impl AEGIS256 {
    pub const NAME: &'static str = "AEGIS-256";
    pub const KEY_SIZE: usize = 32;
    pub const NONCE_SIZE: usize = 32;
    pub const TAG_SIZES: [usize; 2] = [16, 32];

    pub fn new(key: &[u8; 32], tag_size: usize) -> Result<Self, AEGISError> {
        if !Self::TAG_SIZES.contains(&tag_size) {
            return Err(AEGISError::Tag);
        }
        Ok(Self { key: *key, tag_size, state: [[0; 16]; 6] })
    }

    pub fn tag_size(&self) -> usize {
        self.tag_size
    }

    pub fn request<'a>(&'a self, nonce: &'a [u8; 32], associated: &'a [u8]) -> CipherProviderRequest<'a> {
        CipherProviderRequest::new(Self::NAME, &self.key).with_nonce(nonce).with_associated(associated).with_tag_size(self.tag_size)
    }

    pub fn encrypt(&self, nonce: &[u8; 32], associated: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, AEGISError> {
        match CipherProviders::encrypt(&self.request(nonce, associated), plaintext)? {
            Some(ciphertext) => Ok(ciphertext),
            None => todo!(),
        }
    }

    pub fn decrypt(&self, nonce: &[u8; 32], associated: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, AEGISError> {
        match CipherProviders::decrypt(&self.request(nonce, associated), ciphertext)? {
            Some(plaintext) => Ok(plaintext),
            None => todo!(),
        }
    }
}

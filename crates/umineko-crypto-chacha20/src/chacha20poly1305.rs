use alloc::vec::Vec;
use crate::errors::ChaCha20Error;

use umineko_helpers::provider::{CipherProviderRequest, CipherProviders};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChaCha20Poly1305 {
    key: [u8; 32],
}

impl ChaCha20Poly1305 {
    pub const NAME: &'static str = "ChaCha20-Poly1305";
    pub const KEY_SIZE: usize = 32;
    pub const NONCE_SIZE: usize = 12;
    pub const TAG_SIZE: usize = 16;

    pub fn new(key: &[u8; 32]) -> Self {
        Self { key: *key }
    }

    pub fn request<'a>(&'a self, nonce: &'a [u8; 12], associated: &'a [u8]) -> CipherProviderRequest<'a> {
        CipherProviderRequest::new(Self::NAME, &self.key).with_nonce(nonce).with_associated(associated)
    }

    pub fn encrypt(&self, nonce: &[u8; 12], associated: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, ChaCha20Error> {
        match CipherProviders::encrypt(&self.request(nonce, associated), plaintext)? {
            Some(ciphertext) => Ok(ciphertext),
            None => todo!(),
        }
    }

    pub fn decrypt(&self, nonce: &[u8; 12], associated: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, ChaCha20Error> {
        match CipherProviders::decrypt(&self.request(nonce, associated), ciphertext)? {
            Some(plaintext) => Ok(plaintext),
            None => todo!(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XChaCha20Poly1305 {
    key: [u8; 32],
}

impl XChaCha20Poly1305 {
    pub const NAME: &'static str = "XChaCha20-Poly1305";
    pub const KEY_SIZE: usize = 32;
    pub const NONCE_SIZE: usize = 24;
    pub const TAG_SIZE: usize = 16;

    pub fn new(key: &[u8; 32]) -> Self {
        Self { key: *key }
    }

    pub fn request<'a>(&'a self, nonce: &'a [u8; 24], associated: &'a [u8]) -> CipherProviderRequest<'a> {
        CipherProviderRequest::new(Self::NAME, &self.key).with_nonce(nonce).with_associated(associated)
    }

    pub fn encrypt(&self, nonce: &[u8; 24], associated: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, ChaCha20Error> {
        match CipherProviders::encrypt(&self.request(nonce, associated), plaintext)? {
            Some(ciphertext) => Ok(ciphertext),
            None => todo!(),
        }
    }

    pub fn decrypt(&self, nonce: &[u8; 24], associated: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, ChaCha20Error> {
        match CipherProviders::decrypt(&self.request(nonce, associated), ciphertext)? {
            Some(plaintext) => Ok(plaintext),
            None => todo!(),
        }
    }
}

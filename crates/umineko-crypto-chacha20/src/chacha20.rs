use alloc::vec::Vec;

use umineko_helpers::provider::{CipherProviderRequest, CipherProviders};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChaCha20 {
    key: [u8; 32],
    nonce: [u8; 12],
    counter: u32,
    state: [u32; 16],
}

impl ChaCha20 {
    pub const NAME: &'static str = "ChaCha20";
    pub const KEY_SIZE: usize = 32;
    pub const NONCE_SIZE: usize = 12;
    pub const BLOCK_SIZE: usize = 64;
    pub const ROUNDS: usize = 20;

    pub fn new(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> Self {
        Self { key: *key, nonce: *nonce, counter, state: [0; 16] }
    }

    pub fn counter(&self) -> u32 {
        self.counter
    }

    pub fn request(&self, counter: u32) -> CipherProviderRequest<'_> {
        CipherProviderRequest::new(Self::NAME, &self.key).with_nonce(&self.nonce).with_counter(counter)
    }

    pub fn apply(&mut self, data: &[u8]) -> Vec<u8> {
        let request = self.request(self.counter);
        match CipherProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.encrypt(&request, data)) {
            Some(output) => {
                self.counter = self.counter.wrapping_add(data.len().div_ceil(Self::BLOCK_SIZE) as u32);
                output
            }
            None => todo!(),
        }
    }

    pub fn block(&self, counter: u32) -> [u8; 64] {
        let request = self.request(counter);
        match CipherProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.encrypt(&request, &[0; 64])) {
            Some(output) if output.len() == Self::BLOCK_SIZE => {
                let mut block = [0; 64];
                block.copy_from_slice(&output);
                block
            }
            _ => todo!(),
        }
    }

    pub fn reset(&mut self, counter: u32) {
        self.counter = counter;
        self.state = [0; 16];
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XChaCha20 {
    key: [u8; 32],
    nonce: [u8; 24],
    counter: u32,
    inner: Option<ChaCha20>,
}

impl XChaCha20 {
    pub const NAME: &'static str = "XChaCha20";
    pub const KEY_SIZE: usize = 32;
    pub const NONCE_SIZE: usize = 24;
    pub const BLOCK_SIZE: usize = 64;

    pub fn new(key: &[u8; 32], nonce: &[u8; 24], counter: u32) -> Self {
        Self { key: *key, nonce: *nonce, counter, inner: None }
    }

    pub fn counter(&self) -> u32 {
        self.counter
    }

    pub fn request(&self, counter: u32) -> CipherProviderRequest<'_> {
        CipherProviderRequest::new(Self::NAME, &self.key).with_nonce(&self.nonce).with_counter(counter)
    }

    pub fn apply(&mut self, data: &[u8]) -> Vec<u8> {
        let request = self.request(self.counter);
        match CipherProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.encrypt(&request, data)) {
            Some(output) => {
                self.counter = self.counter.wrapping_add(data.len().div_ceil(Self::BLOCK_SIZE) as u32);
                output
            }
            None => todo!(),
        }
    }

    pub fn reset(&mut self, counter: u32) {
        self.counter = counter;
        self.inner = None;
    }

    pub fn subkey(key: &[u8; 32], nonce: &[u8; 16]) -> [u8; 32] {
        todo!()
    }
}

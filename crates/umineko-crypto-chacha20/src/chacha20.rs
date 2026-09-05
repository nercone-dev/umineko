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
    /// The words of "expand 32-byte k", which open every state.
    pub const CONSTANTS: [u32; 4] = [0x6170_7865, 0x3320_646E, 0x7962_2D32, 0x6B20_6574];

    pub fn new(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> Self {
        Self { key: *key, nonce: *nonce, counter, state: Self::state(key, nonce, counter) }
    }

    pub fn counter(&self) -> u32 {
        self.counter
    }

    pub fn request(&self, counter: u32) -> CipherProviderRequest<'_> {
        CipherProviderRequest::new(Self::NAME, &self.key).with_nonce(&self.nonce).with_counter(counter)
    }

    /// The sixteen words that open one block, from the constants, the key, the counter and the nonce.
    pub fn state(key: &[u8; 32], nonce: &[u8], counter: u32) -> [u32; 16] {
        let mut state = [0; 16];
        state[..4].copy_from_slice(&Self::CONSTANTS);
        for (word, chunk) in state[4..12].iter_mut().zip(key.chunks_exact(4)) {
            *word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        state[12] = counter;
        for (word, chunk) in state[13..].iter_mut().zip(nonce.chunks_exact(4)) {
            *word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        state
    }

    pub fn quarter(state: &mut [u32; 16], lanes: [usize; 4]) {
        let [a, b, c, d] = lanes;
        state[a] = state[a].wrapping_add(state[b]);
        state[d] = (state[d] ^ state[a]).rotate_left(16);
        state[c] = state[c].wrapping_add(state[d]);
        state[b] = (state[b] ^ state[c]).rotate_left(12);
        state[a] = state[a].wrapping_add(state[b]);
        state[d] = (state[d] ^ state[a]).rotate_left(8);
        state[c] = state[c].wrapping_add(state[d]);
        state[b] = (state[b] ^ state[c]).rotate_left(7);
    }

    /// Ten double rounds over the columns and the diagonals of the state.
    pub fn permute(state: &mut [u32; 16]) {
        for _ in 0..Self::ROUNDS / 2 {
            Self::quarter(state, [0, 4, 8, 12]);
            Self::quarter(state, [1, 5, 9, 13]);
            Self::quarter(state, [2, 6, 10, 14]);
            Self::quarter(state, [3, 7, 11, 15]);
            Self::quarter(state, [0, 5, 10, 15]);
            Self::quarter(state, [1, 6, 11, 12]);
            Self::quarter(state, [2, 7, 8, 13]);
            Self::quarter(state, [3, 4, 9, 14]);
        }
    }

    pub fn keystream(state: &[u32; 16]) -> [u8; 64] {
        let mut working = *state;
        Self::permute(&mut working);
        let mut block = [0; 64];
        for (chunk, (value, initial)) in block.chunks_exact_mut(4).zip(working.into_iter().zip(state)) {
            chunk.copy_from_slice(&value.wrapping_add(*initial).to_le_bytes());
        }
        block
    }

    pub fn apply(&mut self, data: &[u8]) -> Vec<u8> {
        let request = self.request(self.counter);
        match CipherProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.encrypt(&request, data)) {
            Some(output) => {
                self.counter = self.counter.wrapping_add(data.len().div_ceil(Self::BLOCK_SIZE) as u32);
                output
            }
            None => {
                let mut output = data.to_vec();
                for part in output.chunks_mut(Self::BLOCK_SIZE) {
                    let block = Self::keystream(&Self::state(&self.key, &self.nonce, self.counter));
                    for (target, source) in part.iter_mut().zip(block) {
                        *target ^= source;
                    }
                    self.counter = self.counter.wrapping_add(1);
                }
                self.state = Self::state(&self.key, &self.nonce, self.counter);
                output
            }
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
            Some(_) => [0; 64],
            None => Self::keystream(&Self::state(&self.key, &self.nonce, counter)),
        }
    }

    pub fn reset(&mut self, counter: u32) {
        self.counter = counter;
        self.state = Self::state(&self.key, &self.nonce, counter);
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

    /// The inner cipher, over the subkey of the first sixteen nonce bytes and the last eight.
    pub fn inner(&self) -> ChaCha20 {
        let mut head = [0; 16];
        head.copy_from_slice(&self.nonce[..16]);
        let mut nonce = [0; 12];
        nonce[4..].copy_from_slice(&self.nonce[16..]);
        ChaCha20::new(&Self::subkey(&self.key, &head), &nonce, self.counter)
    }

    pub fn apply(&mut self, data: &[u8]) -> Vec<u8> {
        let request = self.request(self.counter);
        match CipherProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.encrypt(&request, data)) {
            Some(output) => {
                self.counter = self.counter.wrapping_add(data.len().div_ceil(Self::BLOCK_SIZE) as u32);
                output
            }
            None => {
                let mut inner = self.inner.take().unwrap_or_else(|| self.inner());
                let output = inner.apply(data);
                self.counter = inner.counter();
                self.inner = Some(inner);
                output
            }
        }
    }

    pub fn reset(&mut self, counter: u32) {
        self.counter = counter;
        self.inner = None;
    }

    /// The subkey of HChaCha20, which is the permuted state without the feed forward.
    pub fn subkey(key: &[u8; 32], nonce: &[u8; 16]) -> [u8; 32] {
        let mut state = ChaCha20::state(key, &nonce[4..], u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]));
        ChaCha20::permute(&mut state);
        let mut subkey = [0; 32];
        for (chunk, word) in subkey.chunks_exact_mut(4).zip(state[..4].iter().chain(&state[12..])) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        subkey
    }
}

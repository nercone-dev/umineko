use alloc::vec::Vec;
use core::fmt;
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
        match self {
            Self::ECB => None,
            Self::CBC | Self::CFB | Self::OFB | Self::CTR => Some(DES::BLOCK_SIZE),
        }
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

    pub fn nonce(&self, nonce: &[u8]) -> Result<u64, DESError> {
        match self.nonce_size() {
            None => Ok(0),
            Some(size) if nonce.len() == size => Ok(u64::from_be_bytes(nonce.try_into().unwrap_or([0; 8]))),
            Some(_) => Err(DESError::Nonce),
        }
    }

    /// The plaintext under one block transform, padded and chained the way the mode asks.
    pub fn encrypt(&self, nonce: &[u8], plaintext: &[u8], cipher: impl Fn(u64) -> u64) -> Result<Vec<u8>, DESError> {
        let mut chain = self.nonce(nonce)?;
        let mut data = plaintext.to_vec();
        if self.padded() {
            DES::pad(&mut data);
        }
        for block in data.chunks_mut(DES::BLOCK_SIZE) {
            let value = DES::value(block);
            let output = match self {
                Self::ECB => cipher(value),
                Self::CBC => {
                    chain = cipher(value ^ chain);
                    chain
                }
                Self::CFB => {
                    chain = cipher(chain) ^ value;
                    chain
                }
                Self::OFB => {
                    chain = cipher(chain);
                    chain ^ value
                }
                Self::CTR => {
                    let output = cipher(chain) ^ value;
                    chain = chain.wrapping_add(1);
                    output
                }
            };
            DES::place(block, output);
        }
        Ok(data)
    }

    pub fn decrypt(&self, nonce: &[u8], ciphertext: &[u8], cipher: impl Fn(u64) -> u64, decipher: impl Fn(u64) -> u64) -> Result<Vec<u8>, DESError> {
        let mut chain = self.nonce(nonce)?;
        if self.padded() && (ciphertext.is_empty() || ciphertext.len() % DES::BLOCK_SIZE != 0) {
            return Err(DESError::Length);
        }
        let mut data = ciphertext.to_vec();
        for block in data.chunks_mut(DES::BLOCK_SIZE) {
            let value = DES::value(block);
            let output = match self {
                Self::ECB => decipher(value),
                Self::CBC => {
                    let output = decipher(value) ^ chain;
                    chain = value;
                    output
                }
                Self::CFB => {
                    let output = cipher(chain) ^ value;
                    chain = value;
                    output
                }
                Self::OFB => {
                    chain = cipher(chain);
                    chain ^ value
                }
                Self::CTR => {
                    let output = cipher(chain) ^ value;
                    chain = chain.wrapping_add(1);
                    output
                }
            };
            DES::place(block, output);
        }
        if self.padded() {
            DES::unpad(&mut data)?;
        }
        Ok(data)
    }
}

impl fmt::Display for DESMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
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
    pub const ROUNDS: usize = 16;
    pub const INITIAL: [u8; 64] = [
        58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
    ];
    pub const FINAL: [u8; 64] = [
        40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
    ];
    pub const EXPANSION: [u8; 48] = [
        32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11,
        12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21,
        22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
    ];
    pub const PERMUTATION: [u8; 32] = [
        16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
        2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25,
    ];
    pub const CHOICE: [u8; 56] = [
        57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4,
    ];
    pub const SELECTION: [u8; 48] = [
        14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
        23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
    ];
    pub const SHIFTS: [u8; 16] = [
        1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1,
    ];
    pub const BOXES: [u8; 512] = [
        14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
        0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
        4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
        15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
        15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
        3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
        0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
        13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
        10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
        13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
        13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
        1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
        7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
        13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
        10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
        3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
        2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
        14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
        4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
        11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
        12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
        10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
        9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
        4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
        4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
        13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
        1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
        6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
        13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
        1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
        7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
        2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
    ];

    pub fn new(mode: DESMode, key: &[u8; 8]) -> Self {
        Self { mode, key: *key, round_keys: Self::expand(key) }
    }

    pub fn mode(&self) -> DESMode {
        self.mode
    }

    /// The bits of `value` that `table` names, counted from the most significant of `width`.
    pub fn permute(value: u64, table: &[u8], width: usize) -> u64 {
        let mut permuted = 0;
        for (index, position) in table.iter().enumerate() {
            permuted |= ((value >> (width - *position as usize)) & 1) << (table.len() - 1 - index);
        }
        permuted
    }

    pub fn rotate(half: u64, places: u8) -> u64 {
        ((half << places) | (half >> (28 - places))) & 0x0FFF_FFFF
    }

    pub fn expand(key: &[u8; 8]) -> [[u8; 6]; 16] {
        let chosen = Self::permute(u64::from_be_bytes(*key), &Self::CHOICE, 64);
        let (mut left, mut right) = (chosen >> 28, chosen & 0x0FFF_FFFF);
        let mut keys = [[0; 6]; 16];
        for (round, key) in keys.iter_mut().enumerate() {
            left = Self::rotate(left, Self::SHIFTS[round]);
            right = Self::rotate(right, Self::SHIFTS[round]);
            let selected = Self::permute((left << 28) | right, &Self::SELECTION, 56);
            key.copy_from_slice(&selected.to_be_bytes()[2..]);
        }
        keys
    }

    /// The round function, which expands one half, mixes the round key and runs the boxes.
    pub fn feistel(half: u32, key: &[u8; 6]) -> u32 {
        let mut round = [0; 8];
        round[2..].copy_from_slice(key);
        let mixed = Self::permute(half as u64, &Self::EXPANSION, 32) ^ u64::from_be_bytes(round);
        let mut output = 0u32;
        for index in 0..8 {
            let group = ((mixed >> (42 - 6 * index)) & 0x3F) as usize;
            let row = ((group & 0x20) >> 4) | (group & 1);
            let column = (group >> 1) & 0x0F;
            output |= (Self::BOXES[index * 64 + row * 16 + column] as u32) << (28 - 4 * index);
        }
        Self::permute(output as u64, &Self::PERMUTATION, 32) as u32
    }

    /// One block through the sixteen rounds, in the order the round keys arrive.
    pub fn transform(block: u64, keys: &[[u8; 6]; 16], forward: bool) -> u64 {
        let initial = Self::permute(block, &Self::INITIAL, 64);
        let (mut left, mut right) = ((initial >> 32) as u32, initial as u32);
        for round in 0..Self::ROUNDS {
            let key = match forward {
                true => keys[round],
                false => keys[Self::ROUNDS - 1 - round],
            };
            let next = left ^ Self::feistel(right, &key);
            left = right;
            right = next;
        }
        Self::permute(((right as u64) << 32) | left as u64, &Self::FINAL, 64)
    }

    pub fn value(block: &[u8]) -> u64 {
        let mut value = [0; 8];
        value[..block.len()].copy_from_slice(block);
        u64::from_be_bytes(value)
    }

    pub fn place(block: &mut [u8], value: u64) {
        block.copy_from_slice(&value.to_be_bytes()[..block.len()]);
    }

    /// One block of trailing padding, as PKCS #7 describes it.
    pub fn pad(data: &mut Vec<u8>) {
        let padding = Self::BLOCK_SIZE - data.len() % Self::BLOCK_SIZE;
        data.resize(data.len() + padding, padding as u8);
    }

    pub fn unpad(data: &mut Vec<u8>) -> Result<(), DESError> {
        let padding = *data.last().ok_or(DESError::Padding)? as usize;
        if padding == 0 || padding > Self::BLOCK_SIZE || padding > data.len() {
            return Err(DESError::Padding);
        }
        let length = data.len() - padding;
        match data[length..].iter().all(|byte| *byte as usize == padding) {
            true => {
                data.truncate(length);
                Ok(())
            }
            false => Err(DESError::Padding),
        }
    }

    pub fn request<'a>(&'a self, nonce: &'a [u8]) -> CipherProviderRequest<'a> {
        CipherProviderRequest::new(self.mode.name(false), &self.key).with_nonce(nonce).with_padding(self.mode.padded())
    }

    pub fn encrypt(&self, nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, DESError> {
        match CipherProviders::encrypt(&self.request(nonce), plaintext)? {
            Some(ciphertext) => Ok(ciphertext),
            None => self.mode.encrypt(nonce, plaintext, |block| Self::transform(block, &self.round_keys, true)),
        }
    }

    pub fn decrypt(&self, nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, DESError> {
        match CipherProviders::decrypt(&self.request(nonce), ciphertext)? {
            Some(plaintext) => Ok(plaintext),
            None => self.mode.decrypt(nonce, ciphertext, |block| Self::transform(block, &self.round_keys, true), |block| Self::transform(block, &self.round_keys, false)),
        }
    }

    pub fn encrypt_block(&self, block: &mut [u8; 8]) {
        let request = CipherProviderRequest::new(DESMode::ECB.name(false), &self.key);
        match CipherProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.encrypt(&request, block)) {
            Some(output) if output.len() >= 8 => block.copy_from_slice(&output[..8]),
            Some(_) => (),
            None => {
                let value = Self::transform(u64::from_be_bytes(*block), &self.round_keys, true);
                Self::place(block, value);
            }
        }
    }

    pub fn decrypt_block(&self, block: &mut [u8; 8]) {
        let request = CipherProviderRequest::new(DESMode::ECB.name(false), &self.key);
        match CipherProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.decrypt(&request, block)) {
            Some(output) if output.len() >= 8 => block.copy_from_slice(&output[..8]),
            Some(_) => (),
            None => {
                let value = Self::transform(u64::from_be_bytes(*block), &self.round_keys, false);
                Self::place(block, value);
            }
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

    pub fn ciphers(&self) -> &[DES; 3] {
        &self.ciphers
    }

    /// One block encrypted, decrypted and encrypted again, under the three keys in turn.
    pub fn transform(&self, block: u64, forward: bool) -> u64 {
        let order = match forward {
            true => [(0, true), (1, false), (2, true)],
            false => [(2, false), (1, true), (0, false)],
        };
        let mut value = block;
        for (index, direction) in order {
            value = DES::transform(value, &self.ciphers[index].round_keys, direction);
        }
        value
    }

    pub fn request<'a>(&'a self, nonce: &'a [u8]) -> CipherProviderRequest<'a> {
        CipherProviderRequest::new(self.mode.name(true), &self.key).with_nonce(nonce).with_padding(self.mode.padded())
    }

    pub fn encrypt(&self, nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, DESError> {
        match CipherProviders::encrypt(&self.request(nonce), plaintext)? {
            Some(ciphertext) => Ok(ciphertext),
            None => self.mode.encrypt(nonce, plaintext, |block| self.transform(block, true)),
        }
    }

    pub fn decrypt(&self, nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, DESError> {
        match CipherProviders::decrypt(&self.request(nonce), ciphertext)? {
            Some(plaintext) => Ok(plaintext),
            None => self.mode.decrypt(nonce, ciphertext, |block| self.transform(block, true), |block| self.transform(block, false)),
        }
    }

    pub fn encrypt_block(&self, block: &mut [u8; 8]) {
        let request = CipherProviderRequest::new(DESMode::ECB.name(true), &self.key);
        match CipherProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.encrypt(&request, block)) {
            Some(output) if output.len() >= 8 => block.copy_from_slice(&output[..8]),
            Some(_) => (),
            None => {
                let value = self.transform(u64::from_be_bytes(*block), true);
                DES::place(block, value);
            }
        }
    }

    pub fn decrypt_block(&self, block: &mut [u8; 8]) {
        let request = CipherProviderRequest::new(DESMode::ECB.name(true), &self.key);
        match CipherProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.decrypt(&request, block)) {
            Some(output) if output.len() >= 8 => block.copy_from_slice(&output[..8]),
            Some(_) => (),
            None => {
                let value = self.transform(u64::from_be_bytes(*block), false);
                DES::place(block, value);
            }
        }
    }
}

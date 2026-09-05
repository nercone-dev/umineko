use alloc::vec::Vec;
use core::fmt;
use crate::errors::AESError;

use umineko_helpers::provider::{CipherProviderRequest, CipherProviders};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AES {
    V128,
    V192,
    V256,
}

impl AES {
    pub const BLOCK_SIZE: usize = 16;
    pub const ROUND_KEYS: usize = 15;
    pub const TAG_SIZE: usize = 16;
    /// The powers of two in the field of the cipher, one for each round of the key schedule.
    pub const CONSTANTS: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];
    pub const SBOX: [u8; 256] = [
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
    ];
    pub const INVERSE: [u8; 256] = [
        0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
        0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
        0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
        0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
        0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
        0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
        0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
        0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
        0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
        0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
        0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
        0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
        0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
        0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
        0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
    ];

    pub fn key_size(&self) -> usize {
        match self {
            Self::V128 => 16,
            Self::V192 => 24,
            Self::V256 => 32,
        }
    }

    pub fn rounds(&self) -> usize {
        match self {
            Self::V128 => 10,
            Self::V192 => 12,
            Self::V256 => 14,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::V128 => "AES-128",
            Self::V192 => "AES-192",
            Self::V256 => "AES-256",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "AES-128" => Some(Self::V128),
            "AES-192" => Some(Self::V192),
            "AES-256" => Some(Self::V256),
            _ => None,
        }
    }

    pub fn name(&self, mode: AESMode) -> &'static str {
        match (self, mode) {
            (Self::V128, AESMode::ECB) => "AES-128-ECB",
            (Self::V128, AESMode::CBC) => "AES-128-CBC",
            (Self::V128, AESMode::CFB) => "AES-128-CFB",
            (Self::V128, AESMode::OFB) => "AES-128-OFB",
            (Self::V128, AESMode::CTR) => "AES-128-CTR",
            (Self::V128, AESMode::GCM) => "AES-128-GCM",
            (Self::V128, AESMode::CCM) => "AES-128-CCM",
            (Self::V192, AESMode::ECB) => "AES-192-ECB",
            (Self::V192, AESMode::CBC) => "AES-192-CBC",
            (Self::V192, AESMode::CFB) => "AES-192-CFB",
            (Self::V192, AESMode::OFB) => "AES-192-OFB",
            (Self::V192, AESMode::CTR) => "AES-192-CTR",
            (Self::V192, AESMode::GCM) => "AES-192-GCM",
            (Self::V192, AESMode::CCM) => "AES-192-CCM",
            (Self::V256, AESMode::ECB) => "AES-256-ECB",
            (Self::V256, AESMode::CBC) => "AES-256-CBC",
            (Self::V256, AESMode::CFB) => "AES-256-CFB",
            (Self::V256, AESMode::OFB) => "AES-256-OFB",
            (Self::V256, AESMode::CTR) => "AES-256-CTR",
            (Self::V256, AESMode::GCM) => "AES-256-GCM",
            (Self::V256, AESMode::CCM) => "AES-256-CCM",
        }
    }

    /// The round keys of a sixteen, twenty four or thirty two byte key, unused rounds left at zero.
    pub fn expand(key: &[u8]) -> [[u8; 16]; Self::ROUND_KEYS] {
        let words = key.len() / 4;
        let rounds = words + 6;
        let mut schedule = [[0u8; 4]; Self::ROUND_KEYS * 4];
        for (word, chunk) in schedule.iter_mut().zip(key.chunks_exact(4)) {
            word.copy_from_slice(chunk);
        }
        for index in words..4 * (rounds + 1) {
            let mut word = schedule[index - 1];
            if index % words == 0 {
                word.rotate_left(1);
                word = word.map(|byte| Self::SBOX[byte as usize]);
                word[0] ^= Self::CONSTANTS[index / words - 1];
            } else if words > 6 && index % words == 4 {
                word = word.map(|byte| Self::SBOX[byte as usize]);
            }
            for (byte, previous) in word.iter_mut().zip(schedule[index - words]) {
                *byte ^= previous;
            }
            schedule[index] = word;
        }
        let mut keys = [[0u8; 16]; Self::ROUND_KEYS];
        for (round, key) in keys.iter_mut().enumerate() {
            for (word, source) in key.chunks_exact_mut(4).zip(&schedule[round * 4..round * 4 + 4]) {
                word.copy_from_slice(source);
            }
        }
        keys
    }

    /// The product of two elements in the field of the cipher.
    pub fn multiply(left: u8, right: u8) -> u8 {
        let (mut left, mut right, mut product) = (left, right, 0);
        while right != 0 {
            if right & 1 == 1 {
                product ^= left;
            }
            left = (left << 1) ^ (0x1B * (left >> 7));
            right >>= 1;
        }
        product
    }

    pub fn substitute(state: &mut [u8; 16]) {
        for byte in state.iter_mut() {
            *byte = Self::SBOX[*byte as usize];
        }
    }

    pub fn unsubstitute(state: &mut [u8; 16]) {
        for byte in state.iter_mut() {
            *byte = Self::INVERSE[*byte as usize];
        }
    }

    pub fn shift(state: &mut [u8; 16]) {
        let source = *state;
        for row in 1..4 {
            for column in 0..4 {
                state[row + 4 * column] = source[row + 4 * ((column + row) % 4)];
            }
        }
    }

    pub fn unshift(state: &mut [u8; 16]) {
        let source = *state;
        for row in 1..4 {
            for column in 0..4 {
                state[row + 4 * ((column + row) % 4)] = source[row + 4 * column];
            }
        }
    }

    pub fn mix(state: &mut [u8; 16]) {
        for column in state.chunks_exact_mut(4) {
            let source = [column[0], column[1], column[2], column[3]];
            for (index, byte) in column.iter_mut().enumerate() {
                *byte = Self::multiply(source[index], 2) ^ Self::multiply(source[(index + 1) % 4], 3) ^ source[(index + 2) % 4] ^ source[(index + 3) % 4];
            }
        }
    }

    pub fn unmix(state: &mut [u8; 16]) {
        for column in state.chunks_exact_mut(4) {
            let source = [column[0], column[1], column[2], column[3]];
            for (index, byte) in column.iter_mut().enumerate() {
                *byte = Self::multiply(source[index], 14) ^ Self::multiply(source[(index + 1) % 4], 11) ^ Self::multiply(source[(index + 2) % 4], 13) ^ Self::multiply(source[(index + 3) % 4], 9);
            }
        }
    }

    pub fn exclusive(left: &mut [u8], right: &[u8]) {
        for (target, source) in left.iter_mut().zip(right) {
            *target ^= source;
        }
    }

    pub fn cipher(block: &mut [u8; 16], keys: &[[u8; 16]; Self::ROUND_KEYS], rounds: usize) {
        Self::exclusive(block, &keys[0]);
        for key in keys.iter().take(rounds).skip(1) {
            Self::substitute(block);
            Self::shift(block);
            Self::mix(block);
            Self::exclusive(block, key);
        }
        Self::substitute(block);
        Self::shift(block);
        Self::exclusive(block, &keys[rounds]);
    }

    pub fn decipher(block: &mut [u8; 16], keys: &[[u8; 16]; Self::ROUND_KEYS], rounds: usize) {
        Self::exclusive(block, &keys[rounds]);
        for round in (1..rounds).rev() {
            Self::unshift(block);
            Self::unsubstitute(block);
            Self::exclusive(block, &keys[round]);
            Self::unmix(block);
        }
        Self::unshift(block);
        Self::unsubstitute(block);
        Self::exclusive(block, &keys[0]);
    }

    pub fn block(keys: &[[u8; 16]; Self::ROUND_KEYS], rounds: usize, data: &[u8]) -> [u8; 16] {
        let mut block = [0; 16];
        block[..data.len().min(16)].copy_from_slice(&data[..data.len().min(16)]);
        Self::cipher(&mut block, keys, rounds);
        block
    }

    /// One block of trailing padding, as PKCS #7 describes it.
    pub fn pad(data: &mut Vec<u8>) {
        let padding = Self::BLOCK_SIZE - data.len() % Self::BLOCK_SIZE;
        data.resize(data.len() + padding, padding as u8);
    }

    pub fn unpad(data: &mut Vec<u8>) -> Result<(), AESError> {
        let padding = *data.last().ok_or(AESError::Padding)? as usize;
        if padding == 0 || padding > Self::BLOCK_SIZE || padding > data.len() {
            return Err(AESError::Padding);
        }
        let length = data.len() - padding;
        match data[length..].iter().all(|byte| *byte as usize == padding) {
            true => {
                data.truncate(length);
                Ok(())
            }
            false => Err(AESError::Padding),
        }
    }

    pub fn increment(counter: &mut [u8; 16]) {
        for byte in counter.iter_mut().rev() {
            (*byte, _) = byte.overflowing_add(1);
            if *byte != 0 {
                break;
            }
        }
    }

    /// The counter mode keystream applied to `data`, starting from `counter`.
    pub fn stream(keys: &[[u8; 16]; Self::ROUND_KEYS], rounds: usize, counter: &mut [u8; 16], data: &mut [u8]) {
        for part in data.chunks_mut(Self::BLOCK_SIZE) {
            let mut block = *counter;
            Self::cipher(&mut block, keys, rounds);
            Self::exclusive(part, &block);
            Self::increment(counter);
        }
    }

    /// The product of two elements in the field that authenticates Galois counter mode.
    pub fn product(left: &[u8; 16], right: &[u8; 16]) -> [u8; 16] {
        let (mut product, mut value) = ([0u8; 16], *right);
        for index in 0..128 {
            if left[index / 8] >> (7 - index % 8) & 1 == 1 {
                Self::exclusive(&mut product, &value);
            }
            let odd = value[15] & 1 == 1;
            for position in (1..16).rev() {
                value[position] = (value[position] >> 1) | (value[position - 1] << 7);
            }
            value[0] >>= 1;
            if odd {
                value[0] ^= 0xE1;
            }
        }
        product
    }

    pub fn ghash(key: &[u8; 16], parts: &[&[u8]]) -> [u8; 16] {
        let mut digest = [0u8; 16];
        for part in parts {
            for chunk in part.chunks(Self::BLOCK_SIZE) {
                let mut block = [0u8; 16];
                block[..chunk.len()].copy_from_slice(chunk);
                Self::exclusive(&mut digest, &block);
                digest = Self::product(&digest, key);
            }
        }
        digest
    }

    /// The lengths of the associated data and the ciphertext, as Galois counter mode counts them.
    pub fn lengths(associated: usize, ciphertext: usize) -> [u8; 16] {
        let mut block = [0; 16];
        block[..8].copy_from_slice(&(associated as u64 * 8).to_be_bytes());
        block[8..].copy_from_slice(&(ciphertext as u64 * 8).to_be_bytes());
        block
    }

    /// The tag of Galois counter mode, taken over the ciphertext whichever way the data travels.
    pub fn galois(keys: &[[u8; 16]; Self::ROUND_KEYS], rounds: usize, nonce: &[u8], associated: &[u8], data: &mut [u8], encrypting: bool) -> Result<[u8; 16], AESError> {
        if nonce.is_empty() {
            return Err(AESError::Nonce);
        }
        let key = Self::block(keys, rounds, &[0; 16]);
        let mut counter = [0; 16];
        match nonce.len() {
            12 => {
                counter[..12].copy_from_slice(nonce);
                counter[15] = 1;
            }
            _ => counter = Self::ghash(&key, &[nonce, &Self::lengths(0, nonce.len())]),
        }
        let mut mask = counter;
        Self::cipher(&mut mask, keys, rounds);
        Self::increment(&mut counter);
        if !encrypting {
            let mut tag = Self::ghash(&key, &[associated, data, &Self::lengths(associated.len(), data.len())]);
            Self::stream(keys, rounds, &mut counter, data);
            Self::exclusive(&mut tag, &mask);
            return Ok(tag);
        }
        Self::stream(keys, rounds, &mut counter, data);
        let mut tag = Self::ghash(&key, &[associated, data, &Self::lengths(associated.len(), data.len())]);
        Self::exclusive(&mut tag, &mask);
        Ok(tag)
    }

    /// The blocks that the counter with cipher block chaining mode authenticates.
    pub fn formatted(nonce: &[u8], associated: &[u8], length: usize) -> Result<Vec<u8>, AESError> {
        if nonce.len() < 7 || nonce.len() > 13 {
            return Err(AESError::Nonce);
        }
        let counted = 15 - nonce.len();
        if counted < 8 && length >= 1 << (counted * 8) {
            return Err(AESError::Length);
        }
        let mut blocks = Vec::with_capacity(32 + associated.len() + length);
        blocks.push((!associated.is_empty() as u8) << 6 | ((Self::TAG_SIZE as u8 - 2) / 2) << 3 | (counted as u8 - 1));
        blocks.extend_from_slice(nonce);
        blocks.extend_from_slice(&(length as u64).to_be_bytes()[8 - counted.min(8)..]);
        blocks.resize(Self::BLOCK_SIZE, 0);
        if !associated.is_empty() {
            match associated.len() {
                length if length < 0xFF00 => blocks.extend_from_slice(&(length as u16).to_be_bytes()),
                length if length <= u32::MAX as usize => {
                    blocks.extend_from_slice(&[0xFF, 0xFE]);
                    blocks.extend_from_slice(&(length as u32).to_be_bytes());
                }
                length => {
                    blocks.extend_from_slice(&[0xFF, 0xFF]);
                    blocks.extend_from_slice(&(length as u64).to_be_bytes());
                }
            }
            blocks.extend_from_slice(associated);
            blocks.resize(blocks.len().div_ceil(Self::BLOCK_SIZE) * Self::BLOCK_SIZE, 0);
        }
        Ok(blocks)
    }

    pub fn counted(nonce: &[u8], index: u64) -> [u8; 16] {
        let counted = 15 - nonce.len();
        let mut counter = [0; 16];
        counter[0] = counted as u8 - 1;
        counter[1..1 + nonce.len()].copy_from_slice(nonce);
        counter[16 - counted.min(8)..].copy_from_slice(&index.to_be_bytes()[8 - counted.min(8)..]);
        counter
    }

    /// The authentication tag of the counter with cipher block chaining mode, over the plaintext.
    pub fn chained(keys: &[[u8; 16]; Self::ROUND_KEYS], rounds: usize, nonce: &[u8], associated: &[u8], plaintext: &[u8]) -> Result<[u8; 16], AESError> {
        let mut blocks = Self::formatted(nonce, associated, plaintext.len())?;
        blocks.extend_from_slice(plaintext);
        blocks.resize(blocks.len().div_ceil(Self::BLOCK_SIZE) * Self::BLOCK_SIZE, 0);
        let mut digest = [0u8; 16];
        for block in blocks.chunks_exact(Self::BLOCK_SIZE) {
            Self::exclusive(&mut digest, block);
            Self::cipher(&mut digest, keys, rounds);
        }
        let mut mask = Self::counted(nonce, 0);
        Self::cipher(&mut mask, keys, rounds);
        Self::exclusive(&mut digest, &mask);
        Ok(digest)
    }

    pub fn different(left: &[u8], right: &[u8]) -> bool {
        let mut difference = (left.len() != right.len()) as u8;
        for (first, second) in left.iter().zip(right) {
            difference |= first ^ second;
        }
        difference != 0
    }

    pub fn encrypt(mode: AESMode, keys: &[[u8; 16]; Self::ROUND_KEYS], rounds: usize, nonce: &[u8], associated: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, AESError> {
        if let Some(size) = mode.nonce_size() {
            if nonce.len() != size && !matches!(mode, AESMode::GCM | AESMode::CCM) {
                return Err(AESError::Nonce);
            }
        }
        let mut data = plaintext.to_vec();
        match mode {
            AESMode::ECB => {
                Self::pad(&mut data);
                for block in data.chunks_exact_mut(Self::BLOCK_SIZE) {
                    let mut state = [0; 16];
                    state.copy_from_slice(block);
                    Self::cipher(&mut state, keys, rounds);
                    block.copy_from_slice(&state);
                }
            }
            AESMode::CBC => {
                Self::pad(&mut data);
                let mut chain = [0; 16];
                chain.copy_from_slice(nonce);
                for block in data.chunks_exact_mut(Self::BLOCK_SIZE) {
                    Self::exclusive(block, &chain);
                    chain.copy_from_slice(block);
                    Self::cipher(&mut chain, keys, rounds);
                    block.copy_from_slice(&chain);
                }
            }
            AESMode::CFB => {
                let mut chain = [0; 16];
                chain.copy_from_slice(nonce);
                for block in data.chunks_mut(Self::BLOCK_SIZE) {
                    Self::cipher(&mut chain, keys, rounds);
                    Self::exclusive(block, &chain);
                    chain[..block.len()].copy_from_slice(block);
                }
            }
            AESMode::OFB => {
                let mut chain = [0; 16];
                chain.copy_from_slice(nonce);
                for block in data.chunks_mut(Self::BLOCK_SIZE) {
                    Self::cipher(&mut chain, keys, rounds);
                    Self::exclusive(block, &chain);
                }
            }
            AESMode::CTR => {
                let mut counter = [0; 16];
                counter.copy_from_slice(nonce);
                Self::stream(keys, rounds, &mut counter, &mut data);
            }
            AESMode::GCM => {
                let tag = Self::galois(keys, rounds, nonce, associated, &mut data, true)?;
                data.extend_from_slice(&tag);
            }
            AESMode::CCM => {
                let tag = Self::chained(keys, rounds, nonce, associated, &data)?;
                let mut counter = Self::counted(nonce, 1);
                Self::stream(keys, rounds, &mut counter, &mut data);
                data.extend_from_slice(&tag);
            }
        }
        Ok(data)
    }

    pub fn decrypt(mode: AESMode, keys: &[[u8; 16]; Self::ROUND_KEYS], rounds: usize, nonce: &[u8], associated: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, AESError> {
        if let Some(size) = mode.nonce_size() {
            if nonce.len() != size && !matches!(mode, AESMode::GCM | AESMode::CCM) {
                return Err(AESError::Nonce);
            }
        }
        if mode.padded() && (ciphertext.is_empty() || ciphertext.len() % Self::BLOCK_SIZE != 0) {
            return Err(AESError::Length);
        }
        if mode.authenticated() && ciphertext.len() < Self::TAG_SIZE {
            return Err(AESError::Length);
        }
        let mut data = match mode.authenticated() {
            true => ciphertext[..ciphertext.len() - Self::TAG_SIZE].to_vec(),
            false => ciphertext.to_vec(),
        };
        match mode {
            AESMode::ECB => {
                for block in data.chunks_exact_mut(Self::BLOCK_SIZE) {
                    let mut state = [0; 16];
                    state.copy_from_slice(block);
                    Self::decipher(&mut state, keys, rounds);
                    block.copy_from_slice(&state);
                }
                Self::unpad(&mut data)?;
            }
            AESMode::CBC => {
                let mut chain = [0; 16];
                chain.copy_from_slice(nonce);
                for block in data.chunks_exact_mut(Self::BLOCK_SIZE) {
                    let mut state = [0; 16];
                    state.copy_from_slice(block);
                    Self::decipher(&mut state, keys, rounds);
                    Self::exclusive(&mut state, &chain);
                    chain.copy_from_slice(block);
                    block.copy_from_slice(&state);
                }
                Self::unpad(&mut data)?;
            }
            AESMode::CFB => {
                let mut chain = [0; 16];
                chain.copy_from_slice(nonce);
                for block in data.chunks_mut(Self::BLOCK_SIZE) {
                    let mut next = [0; 16];
                    next[..block.len()].copy_from_slice(block);
                    Self::cipher(&mut chain, keys, rounds);
                    Self::exclusive(block, &chain);
                    chain = next;
                }
            }
            AESMode::OFB => {
                let mut chain = [0; 16];
                chain.copy_from_slice(nonce);
                for block in data.chunks_mut(Self::BLOCK_SIZE) {
                    Self::cipher(&mut chain, keys, rounds);
                    Self::exclusive(block, &chain);
                }
            }
            AESMode::CTR => {
                let mut counter = [0; 16];
                counter.copy_from_slice(nonce);
                Self::stream(keys, rounds, &mut counter, &mut data);
            }
            AESMode::GCM => {
                let tag = Self::galois(keys, rounds, nonce, associated, &mut data, false)?;
                if Self::different(&tag, &ciphertext[ciphertext.len() - Self::TAG_SIZE..]) {
                    return Err(AESError::Authentication);
                }
            }
            AESMode::CCM => {
                let mut counter = Self::counted(nonce, 1);
                Self::stream(keys, rounds, &mut counter, &mut data);
                let tag = Self::chained(keys, rounds, nonce, associated, &data)?;
                if Self::different(&tag, &ciphertext[ciphertext.len() - Self::TAG_SIZE..]) {
                    return Err(AESError::Authentication);
                }
            }
        }
        Ok(data)
    }
}

impl fmt::Display for AES {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AESMode {
    ECB,
    CBC,
    CFB,
    OFB,
    CTR,
    GCM,
    CCM,
}

impl AESMode {
    pub fn authenticated(&self) -> bool {
        matches!(self, Self::GCM | Self::CCM)
    }

    pub fn padded(&self) -> bool {
        matches!(self, Self::ECB | Self::CBC)
    }

    /// The nonce length the mode expects, which the authenticated modes only recommend.
    pub fn nonce_size(&self) -> Option<usize> {
        match self {
            Self::ECB => None,
            Self::CBC | Self::CFB | Self::OFB | Self::CTR => Some(16),
            Self::GCM | Self::CCM => Some(12),
        }
    }

    pub fn tag_size(&self) -> Option<usize> {
        match self.authenticated() {
            true => Some(AES::TAG_SIZE),
            false => None,
        }
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
}

impl fmt::Display for AESMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AES128 {
    mode: AESMode,
    key: [u8; 16],
    round_keys: [[u8; 16]; AES::ROUND_KEYS],
}

impl AES128 {
    pub const VARIANT: AES = AES::V128;
    pub const KEY_SIZE: usize = 16;
    pub const BLOCK_SIZE: usize = 16;
    pub const ROUNDS: usize = 10;

    pub fn new(mode: AESMode, key: &[u8; 16]) -> Self {
        Self { mode, key: *key, round_keys: AES::expand(key) }
    }

    pub fn mode(&self) -> AESMode {
        self.mode
    }

    pub fn request<'a>(&'a self, nonce: &'a [u8], associated: &'a [u8]) -> CipherProviderRequest<'a> {
        CipherProviderRequest::new(Self::VARIANT.name(self.mode), &self.key).with_nonce(nonce).with_associated(associated).with_padding(self.mode.padded())
    }

    pub fn encrypt(&self, nonce: &[u8], associated: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, AESError> {
        match CipherProviders::encrypt(&self.request(nonce, associated), plaintext)? {
            Some(ciphertext) => Ok(ciphertext),
            None => AES::encrypt(self.mode, &self.round_keys, Self::ROUNDS, nonce, associated, plaintext),
        }
    }

    pub fn decrypt(&self, nonce: &[u8], associated: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, AESError> {
        match CipherProviders::decrypt(&self.request(nonce, associated), ciphertext)? {
            Some(plaintext) => Ok(plaintext),
            None => AES::decrypt(self.mode, &self.round_keys, Self::ROUNDS, nonce, associated, ciphertext),
        }
    }

    pub fn encrypt_block(&self, block: &mut [u8; 16]) {
        let request = CipherProviderRequest::new(Self::VARIANT.name(AESMode::ECB), &self.key);
        match CipherProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.encrypt(&request, block)) {
            Some(output) if output.len() >= 16 => block.copy_from_slice(&output[..16]),
            Some(_) => (),
            None => AES::cipher(block, &self.round_keys, Self::ROUNDS),
        }
    }

    pub fn decrypt_block(&self, block: &mut [u8; 16]) {
        let request = CipherProviderRequest::new(Self::VARIANT.name(AESMode::ECB), &self.key);
        match CipherProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.decrypt(&request, block)) {
            Some(output) if output.len() >= 16 => block.copy_from_slice(&output[..16]),
            Some(_) => (),
            None => AES::decipher(block, &self.round_keys, Self::ROUNDS),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AES192 {
    mode: AESMode,
    key: [u8; 24],
    round_keys: [[u8; 16]; AES::ROUND_KEYS],
}

impl AES192 {
    pub const VARIANT: AES = AES::V192;
    pub const KEY_SIZE: usize = 24;
    pub const BLOCK_SIZE: usize = 16;
    pub const ROUNDS: usize = 12;

    pub fn new(mode: AESMode, key: &[u8; 24]) -> Self {
        Self { mode, key: *key, round_keys: AES::expand(key) }
    }

    pub fn mode(&self) -> AESMode {
        self.mode
    }

    pub fn request<'a>(&'a self, nonce: &'a [u8], associated: &'a [u8]) -> CipherProviderRequest<'a> {
        CipherProviderRequest::new(Self::VARIANT.name(self.mode), &self.key).with_nonce(nonce).with_associated(associated).with_padding(self.mode.padded())
    }

    pub fn encrypt(&self, nonce: &[u8], associated: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, AESError> {
        match CipherProviders::encrypt(&self.request(nonce, associated), plaintext)? {
            Some(ciphertext) => Ok(ciphertext),
            None => AES::encrypt(self.mode, &self.round_keys, Self::ROUNDS, nonce, associated, plaintext),
        }
    }

    pub fn decrypt(&self, nonce: &[u8], associated: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, AESError> {
        match CipherProviders::decrypt(&self.request(nonce, associated), ciphertext)? {
            Some(plaintext) => Ok(plaintext),
            None => AES::decrypt(self.mode, &self.round_keys, Self::ROUNDS, nonce, associated, ciphertext),
        }
    }

    pub fn encrypt_block(&self, block: &mut [u8; 16]) {
        let request = CipherProviderRequest::new(Self::VARIANT.name(AESMode::ECB), &self.key);
        match CipherProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.encrypt(&request, block)) {
            Some(output) if output.len() >= 16 => block.copy_from_slice(&output[..16]),
            Some(_) => (),
            None => AES::cipher(block, &self.round_keys, Self::ROUNDS),
        }
    }

    pub fn decrypt_block(&self, block: &mut [u8; 16]) {
        let request = CipherProviderRequest::new(Self::VARIANT.name(AESMode::ECB), &self.key);
        match CipherProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.decrypt(&request, block)) {
            Some(output) if output.len() >= 16 => block.copy_from_slice(&output[..16]),
            Some(_) => (),
            None => AES::decipher(block, &self.round_keys, Self::ROUNDS),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AES256 {
    mode: AESMode,
    key: [u8; 32],
    round_keys: [[u8; 16]; AES::ROUND_KEYS],
}

impl AES256 {
    pub const VARIANT: AES = AES::V256;
    pub const KEY_SIZE: usize = 32;
    pub const BLOCK_SIZE: usize = 16;
    pub const ROUNDS: usize = 14;

    pub fn new(mode: AESMode, key: &[u8; 32]) -> Self {
        Self { mode, key: *key, round_keys: AES::expand(key) }
    }

    pub fn mode(&self) -> AESMode {
        self.mode
    }

    pub fn request<'a>(&'a self, nonce: &'a [u8], associated: &'a [u8]) -> CipherProviderRequest<'a> {
        CipherProviderRequest::new(Self::VARIANT.name(self.mode), &self.key).with_nonce(nonce).with_associated(associated).with_padding(self.mode.padded())
    }

    pub fn encrypt(&self, nonce: &[u8], associated: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, AESError> {
        match CipherProviders::encrypt(&self.request(nonce, associated), plaintext)? {
            Some(ciphertext) => Ok(ciphertext),
            None => AES::encrypt(self.mode, &self.round_keys, Self::ROUNDS, nonce, associated, plaintext),
        }
    }

    pub fn decrypt(&self, nonce: &[u8], associated: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, AESError> {
        match CipherProviders::decrypt(&self.request(nonce, associated), ciphertext)? {
            Some(plaintext) => Ok(plaintext),
            None => AES::decrypt(self.mode, &self.round_keys, Self::ROUNDS, nonce, associated, ciphertext),
        }
    }

    pub fn encrypt_block(&self, block: &mut [u8; 16]) {
        let request = CipherProviderRequest::new(Self::VARIANT.name(AESMode::ECB), &self.key);
        match CipherProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.encrypt(&request, block)) {
            Some(output) if output.len() >= 16 => block.copy_from_slice(&output[..16]),
            Some(_) => (),
            None => AES::cipher(block, &self.round_keys, Self::ROUNDS),
        }
    }

    pub fn decrypt_block(&self, block: &mut [u8; 16]) {
        let request = CipherProviderRequest::new(Self::VARIANT.name(AESMode::ECB), &self.key);
        match CipherProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.decrypt(&request, block)) {
            Some(output) if output.len() >= 16 => block.copy_from_slice(&output[..16]),
            Some(_) => (),
            None => AES::decipher(block, &self.round_keys, Self::ROUNDS),
        }
    }
}

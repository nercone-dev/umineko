use alloc::vec::Vec;
use core::fmt;
use crate::errors::GOSTError;

use umineko_helpers::provider::{CipherProviderRequest, CipherProviders, HashProviderRequest, HashProviders};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GOST28147Mode {
    ECB,
    CNT,
    CFB,
}

impl GOST28147Mode {
    pub fn padded(&self) -> bool {
        matches!(self, Self::ECB)
    }

    pub fn nonce_size(&self) -> Option<usize> {
        todo!()
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ECB => "ECB",
            Self::CNT => "CNT",
            Self::CFB => "CFB",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GOST28147KeyMeshing {
    None,
    CryptoPro,
}

impl GOST28147KeyMeshing {
    pub const CRYPTOPRO_KEY: [u8; 32] = [0x69, 0x00, 0x72, 0x22, 0x64, 0xC9, 0x04, 0x23, 0x8D, 0x3A, 0xDB, 0x96, 0x46, 0xE9, 0x2A, 0xC4, 0x18, 0xFE, 0xAC, 0x94, 0x00, 0xED, 0x07, 0x12, 0xC0, 0x86, 0xDC, 0xC2, 0xEF, 0x4C, 0xA9, 0x2B];
    pub const CRYPTOPRO_INTERVAL: usize = 1024;

    pub fn interval(&self) -> Option<usize> {
        match self {
            Self::None => None,
            Self::CryptoPro => Some(Self::CRYPTOPRO_INTERVAL),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "id-Gost28147-89-None-KeyMeshing",
            Self::CryptoPro => "id-Gost28147-89-CryptoPro-KeyMeshing",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "id-Gost28147-89-None-KeyMeshing" => Some(Self::None),
            "id-Gost28147-89-CryptoPro-KeyMeshing" => Some(Self::CryptoPro),
            _ => None,
        }
    }
}

impl fmt::Display for GOST28147KeyMeshing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GOST28147SBox {
    TC26Z,
    CryptoProA,
    CryptoProB,
    CryptoProC,
    CryptoProD,
}

impl GOST28147SBox {
    pub fn key_meshing(&self) -> GOST28147KeyMeshing {
        match self {
            Self::TC26Z | Self::CryptoProA | Self::CryptoProB | Self::CryptoProC | Self::CryptoProD => GOST28147KeyMeshing::CryptoPro,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::TC26Z => "id-tc26-gost-28147-param-Z",
            Self::CryptoProA => "id-Gost28147-89-CryptoPro-A-ParamSet",
            Self::CryptoProB => "id-Gost28147-89-CryptoPro-B-ParamSet",
            Self::CryptoProC => "id-Gost28147-89-CryptoPro-C-ParamSet",
            Self::CryptoProD => "id-Gost28147-89-CryptoPro-D-ParamSet",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "id-tc26-gost-28147-param-Z" => Some(Self::TC26Z),
            "id-Gost28147-89-CryptoPro-A-ParamSet" => Some(Self::CryptoProA),
            "id-Gost28147-89-CryptoPro-B-ParamSet" => Some(Self::CryptoProB),
            "id-Gost28147-89-CryptoPro-C-ParamSet" => Some(Self::CryptoProC),
            "id-Gost28147-89-CryptoPro-D-ParamSet" => Some(Self::CryptoProD),
            _ => None,
        }
    }
}

impl fmt::Display for GOST28147SBox {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GOST28147 {
    mode: GOST28147Mode,
    sbox: GOST28147SBox,
    key: [u8; 32],
}

impl GOST28147 {
    pub const NAME: &'static str = "GOST28147";
    pub const KEY_SIZE: usize = 32;
    pub const BLOCK_SIZE: usize = 8;
    pub const MAC_SIZE: usize = 4;
    pub const UKM_SIZE: usize = 8;
    pub const EXPORT_SIZE: usize = 44;

    pub fn name(mode: GOST28147Mode, sbox: GOST28147SBox) -> &'static str {
        match (mode, sbox) {
            (GOST28147Mode::ECB, GOST28147SBox::TC26Z) => "GOST28147-TC26Z-ECB",
            (GOST28147Mode::ECB, GOST28147SBox::CryptoProA) => "GOST28147-CryptoProA-ECB",
            (GOST28147Mode::ECB, GOST28147SBox::CryptoProB) => "GOST28147-CryptoProB-ECB",
            (GOST28147Mode::ECB, GOST28147SBox::CryptoProC) => "GOST28147-CryptoProC-ECB",
            (GOST28147Mode::ECB, GOST28147SBox::CryptoProD) => "GOST28147-CryptoProD-ECB",
            (GOST28147Mode::CNT, GOST28147SBox::TC26Z) => "GOST28147-TC26Z-CNT",
            (GOST28147Mode::CNT, GOST28147SBox::CryptoProA) => "GOST28147-CryptoProA-CNT",
            (GOST28147Mode::CNT, GOST28147SBox::CryptoProB) => "GOST28147-CryptoProB-CNT",
            (GOST28147Mode::CNT, GOST28147SBox::CryptoProC) => "GOST28147-CryptoProC-CNT",
            (GOST28147Mode::CNT, GOST28147SBox::CryptoProD) => "GOST28147-CryptoProD-CNT",
            (GOST28147Mode::CFB, GOST28147SBox::TC26Z) => "GOST28147-TC26Z-CFB",
            (GOST28147Mode::CFB, GOST28147SBox::CryptoProA) => "GOST28147-CryptoProA-CFB",
            (GOST28147Mode::CFB, GOST28147SBox::CryptoProB) => "GOST28147-CryptoProB-CFB",
            (GOST28147Mode::CFB, GOST28147SBox::CryptoProC) => "GOST28147-CryptoProC-CFB",
            (GOST28147Mode::CFB, GOST28147SBox::CryptoProD) => "GOST28147-CryptoProD-CFB",
        }
    }

    pub fn mac_name(sbox: GOST28147SBox) -> &'static str {
        match sbox {
            GOST28147SBox::TC26Z => "IMIT-GOST28147-TC26Z",
            GOST28147SBox::CryptoProA => "IMIT-GOST28147-CryptoProA",
            GOST28147SBox::CryptoProB => "IMIT-GOST28147-CryptoProB",
            GOST28147SBox::CryptoProC => "IMIT-GOST28147-CryptoProC",
            GOST28147SBox::CryptoProD => "IMIT-GOST28147-CryptoProD",
        }
    }

    pub fn new(mode: GOST28147Mode, sbox: GOST28147SBox, key: &[u8; 32]) -> Self {
        Self { mode, sbox, key: *key }
    }

    pub fn mode(&self) -> GOST28147Mode {
        self.mode
    }

    pub fn sbox(&self) -> GOST28147SBox {
        self.sbox
    }

    pub fn request<'a>(&'a self, nonce: &'a [u8]) -> CipherProviderRequest<'a> {
        CipherProviderRequest::new(Self::name(self.mode, self.sbox), &self.key).with_nonce(nonce).with_padding(self.mode.padded())
    }

    pub fn encrypt(&self, nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, GOSTError> {
        match CipherProviders::encrypt(&self.request(nonce), plaintext)? {
            Some(ciphertext) => Ok(ciphertext),
            None => todo!(),
        }
    }

    pub fn decrypt(&self, nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, GOSTError> {
        match CipherProviders::decrypt(&self.request(nonce), ciphertext)? {
            Some(plaintext) => Ok(plaintext),
            None => todo!(),
        }
    }

    pub fn encrypt_block(&self, block: &mut [u8; 8]) {
        let request = CipherProviderRequest::new(Self::name(GOST28147Mode::ECB, self.sbox), &self.key);
        match CipherProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.encrypt(&request, block)) {
            Some(output) if output.len() == block.len() => block.copy_from_slice(&output),
            _ => todo!(),
        }
    }

    pub fn decrypt_block(&self, block: &mut [u8; 8]) {
        let request = CipherProviderRequest::new(Self::name(GOST28147Mode::ECB, self.sbox), &self.key);
        match CipherProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.decrypt(&request, block)) {
            Some(output) if output.len() == block.len() => block.copy_from_slice(&output),
            _ => todo!(),
        }
    }

    pub fn mac(&self, iv: &[u8; 8], data: &[u8], tag: &mut [u8]) -> usize {
        let mut message = alloc::vec![0; data.len().div_ceil(Self::BLOCK_SIZE).max(1) * Self::BLOCK_SIZE];
        message[..data.len()].copy_from_slice(data);
        for (byte, iv) in message.iter_mut().zip(iv) {
            *byte ^= iv;
        }
        match HashProviders::digest(&HashProviderRequest::new(Self::mac_name(self.sbox)).with_key(&self.key), &message, tag) {
            Some(length) => length,
            None => todo!(),
        }
    }

    pub fn export_key(&self, key: &[u8], nonce: &[u8]) -> Result<Vec<u8>, GOSTError> {
        let key: &[u8; 32] = key.try_into().map_err(|_| GOSTError::Key)?;
        let nonce: &[u8; 8] = nonce.try_into().map_err(|_| GOSTError::Nonce)?;
        let mut mac = [0; Self::MAC_SIZE];
        self.mac(nonce, key, &mut mac);
        let mut encrypted = *key;
        for block in encrypted.chunks_exact_mut(Self::BLOCK_SIZE) {
            self.encrypt_block(block.try_into().map_err(|_| GOSTError::Length)?);
        }
        Ok([&nonce[..], &encrypted, &mac].concat())
    }

    pub fn import_key(&self, exported: &[u8], nonce: &[u8]) -> Result<Vec<u8>, GOSTError> {
        if exported.len() != Self::EXPORT_SIZE {
            return Err(GOSTError::Length);
        }
        let nonce: &[u8; 8] = nonce.try_into().map_err(|_| GOSTError::Nonce)?;
        if exported[..Self::UKM_SIZE] != *nonce {
            return Err(GOSTError::Nonce);
        }
        let mut key = [0; Self::KEY_SIZE];
        key.copy_from_slice(&exported[Self::UKM_SIZE..Self::UKM_SIZE + Self::KEY_SIZE]);
        for block in key.chunks_exact_mut(Self::BLOCK_SIZE) {
            self.decrypt_block(block.try_into().map_err(|_| GOSTError::Length)?);
        }
        let mut mac = [0; Self::MAC_SIZE];
        self.mac(nonce, &key, &mut mac);
        let mut difference = 0;
        for (left, right) in mac.iter().zip(&exported[Self::UKM_SIZE + Self::KEY_SIZE..]) {
            difference |= left ^ right;
        }
        match difference {
            0 => Ok(key.to_vec()),
            _ => Err(GOSTError::Authentication),
        }
    }

    pub fn diversify(&self, ukm: &[u8; 8]) -> Result<[u8; 32], GOSTError> {
        let mut key = self.key;
        for byte in ukm {
            let mut included = 0u32;
            let mut excluded = 0u32;
            for (index, word) in key.chunks_exact(4).enumerate() {
                let value = u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
                match (byte >> index) & 1 {
                    1 => included = included.wrapping_add(value),
                    _ => excluded = excluded.wrapping_add(value),
                }
            }
            let iv = [included.to_le_bytes(), excluded.to_le_bytes()].concat();
            let output = Self::new(GOST28147Mode::CFB, self.sbox, &key).encrypt(&iv, &key)?;
            key = output.as_slice().try_into().map_err(|_| GOSTError::Length)?;
        }
        Ok(key)
    }
}

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Once};

use umineko_crypto_gost::{GOST28147, GOST28147Mode, GOST28147SBox, GOSTError};
use umineko_helpers::provider::{CipherProvider, CipherProviderRequest, CipherProviders, HashProvider, HashProviderRequest, HashProviders, Provider, ProviderCategory, ProviderError, ProviderHandle};

fn ecb_encrypt(key: &[u8], data: &[u8]) -> Vec<u8> {
    data.iter().enumerate().map(|(index, byte)| byte.wrapping_add(key[index % 32]).rotate_left(3) ^ 0xA5).collect()
}

fn ecb_decrypt(key: &[u8], data: &[u8]) -> Vec<u8> {
    data.iter().enumerate().map(|(index, byte)| (byte ^ 0xA5).rotate_right(3).wrapping_sub(key[index % 32])).collect()
}

fn cfb(key: &[u8], iv: &[u8], data: &[u8]) -> Vec<u8> {
    data.iter().enumerate().map(|(index, byte)| byte ^ key[(index * 7) % 32] ^ iv[index % iv.len()] ^ index as u8).collect()
}

fn imit(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut state: u64 = 0xCBF29CE484222325;
    for byte in key.iter().chain(data) {
        state = (state ^ *byte as u64).wrapping_mul(0x100000001B3);
    }
    state.to_le_bytes()[..4].to_vec()
}

struct Cipher;

impl Provider for Cipher {
    fn name(&self) -> &'static str {
        "fake-gost28147"
    }

    fn release(&self, _handle: ProviderHandle) {}
}

impl CipherProvider for Cipher {
    fn supports(&self, request: &CipherProviderRequest<'_>) -> bool {
        request.algorithm == GOST28147::name(GOST28147Mode::ECB, GOST28147SBox::TC26Z) || request.algorithm == GOST28147::name(GOST28147Mode::CFB, GOST28147SBox::TC26Z)
    }

    fn encrypt(&self, request: &CipherProviderRequest<'_>, plaintext: &[u8]) -> Result<Vec<u8>, ProviderError> {
        match request.algorithm.ends_with("-ECB") {
            true => Ok(ecb_encrypt(request.key, plaintext)),
            false => Ok(cfb(request.key, request.nonce, plaintext)),
        }
    }

    fn decrypt(&self, request: &CipherProviderRequest<'_>, ciphertext: &[u8]) -> Result<Vec<u8>, ProviderError> {
        match request.algorithm.ends_with("-ECB") {
            true => Ok(ecb_decrypt(request.key, ciphertext)),
            false => Err(ProviderError::Unsupported),
        }
    }
}

struct Imit {
    next: AtomicU64,
    states: Mutex<HashMap<u64, (Vec<u8>, Vec<u8>)>>,
}

impl Provider for Imit {
    fn name(&self) -> &'static str {
        "fake-imit"
    }

    fn release(&self, handle: ProviderHandle) {
        self.states.lock().unwrap().remove(&(handle.value as u64));
    }
}

impl HashProvider for Imit {
    fn supports(&self, request: &HashProviderRequest<'_>) -> bool {
        request.algorithm == GOST28147::mac_name(GOST28147SBox::TC26Z) && request.key.is_some()
    }

    fn open(&self, request: &HashProviderRequest<'_>) -> Result<ProviderHandle, ProviderError> {
        let id = self.next.fetch_add(1, Ordering::SeqCst);
        self.states.lock().unwrap().insert(id, (request.key.unwrap_or_default().to_vec(), Vec::new()));
        Ok(ProviderHandle::new(ProviderCategory::Hash, id as _))
    }

    fn update(&self, handle: ProviderHandle, data: &[u8]) {
        self.states.lock().unwrap().get_mut(&(handle.value as u64)).unwrap().1.extend_from_slice(data);
    }

    fn finalize(&self, handle: ProviderHandle, digest: &mut [u8]) -> usize {
        let (key, data) = self.states.lock().unwrap().get(&(handle.value as u64)).unwrap().clone();
        let length = digest.len().min(4);
        digest[..length].copy_from_slice(&imit(&key, &data)[..length]);
        length
    }

    fn reset(&self, _handle: ProviderHandle) {}

    fn duplicate(&self, handle: ProviderHandle) -> ProviderHandle {
        handle
    }
}

fn install() {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        CipherProviders::global().register(Arc::new(Cipher)).unwrap();
        HashProviders::global().register(Arc::new(Imit { next: AtomicU64::new(1), states: Mutex::new(HashMap::new()) })).unwrap();
    });
}

fn gost28147_imit(iv: &[u8], key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut padded = message.to_vec();
    padded.resize(message.len().div_ceil(8) * 8, 0);
    for index in 0..8 {
        padded[index] ^= iv[index];
    }
    imit(key, &padded)
}

const KEK: [u8; 32] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10];

#[test]
fn imit_with_an_initial_value_xors_it_into_the_first_padded_block_by_rfc9189() {
    install();
    let cipher = GOST28147::new(GOST28147Mode::CNT, GOST28147SBox::TC26Z, &KEK);
    let iv = [0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78];
    for length in [8, 13, 32, 1025] {
        let message: Vec<u8> = (0..length).map(|value| value as u8).collect();
        let mut tag = [0; 4];
        assert_eq!(cipher.mac(&iv, &message, &mut tag), 4);
        assert_eq!(tag.to_vec(), gost28147_imit(&iv, &KEK, &message), "{length}");
    }
}

#[test]
fn kexp28147_and_kimp28147_follow_rfc9189() {
    install();
    let cipher = GOST28147::new(GOST28147Mode::ECB, GOST28147SBox::TC26Z, &KEK);
    let secret: Vec<u8> = (0x40..0x60).collect();
    let iv = [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7];
    let exported = cipher.export_key(&secret, &iv).unwrap();
    let encrypted: Vec<u8> = secret.chunks(8).flat_map(|block| ecb_encrypt(&KEK, block)).collect();
    assert_eq!(exported, [&iv[..], &encrypted, &gost28147_imit(&iv, &KEK, &secret)].concat());
    assert_eq!(cipher.import_key(&exported, &iv).unwrap(), secret);

    let mut tampered = exported.clone();
    tampered[43] ^= 0x01;
    assert_eq!(cipher.import_key(&tampered, &iv), Err(GOSTError::Authentication));
    let mut tampered = exported.clone();
    tampered[8] ^= 0x01;
    assert_eq!(cipher.import_key(&tampered, &iv), Err(GOSTError::Authentication));
    assert_eq!(cipher.import_key(&exported, &[0; 8]), Err(GOSTError::Nonce));
    assert_eq!(cipher.import_key(&exported[..43], &iv), Err(GOSTError::Length));
    assert_eq!(cipher.export_key(&secret[..31], &iv), Err(GOSTError::Key));
    assert_eq!(cipher.export_key(&secret, &iv[..7]), Err(GOSTError::Nonce));
}

#[test]
fn kek_diversification_follows_rfc4357() {
    install();
    let ukm = [0x01, 0x80, 0xFF, 0x00, 0x5A, 0xA5, 0x3C, 0xC3];
    let mut expected = KEK;
    for byte in ukm {
        let words: Vec<u32> = expected.chunks(4).map(|word| u32::from_le_bytes(word.try_into().unwrap())).collect();
        let s1 = (0..8).filter(|bit| (byte >> bit) & 1 == 1).fold(0u32, |sum, bit| sum.wrapping_add(words[bit]));
        let s2 = (0..8).filter(|bit| (byte >> bit) & 1 == 0).fold(0u32, |sum, bit| sum.wrapping_add(words[bit]));
        let iv = [s1.to_le_bytes(), s2.to_le_bytes()].concat();
        expected = cfb(&expected, &iv, &expected).try_into().unwrap();
    }
    let cipher = GOST28147::new(GOST28147Mode::CNT, GOST28147SBox::TC26Z, &KEK);
    assert_eq!(cipher.diversify(&ukm), Ok(expected));
}

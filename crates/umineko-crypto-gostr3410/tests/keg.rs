use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Once};

use umineko_crypto_gost::{GOST28147, GOST28147Mode, GOST28147SBox};
use umineko_crypto_gostr3410::{GOSTR3410, GOSTR3410Error};
use umineko_crypto_hmac::HMACHash;
use umineko_hash_streebog::Streebog;
use umineko_helpers::provider::{CipherProvider, CipherProviderRequest, CipherProviders, ExchangeProvider, ExchangeProviderRequest, ExchangeProviders, HashProvider, HashProviderRequest, HashProviders, Provider, ProviderCategory, ProviderError, ProviderHandle, SignatureProvider, SignatureProviderRequest, SignatureProviders};

fn mix(parts: &[&[u8]], size: usize) -> Vec<u8> {
    let mut state: u64 = 0xCBF29CE484222325;
    for part in parts {
        for byte in part.len().to_le_bytes().iter().chain(part.iter()) {
            state = (state ^ *byte as u64).wrapping_mul(0x100000001B3);
        }
    }
    (0..size).map(|index| {
        state = (state ^ index as u64).wrapping_mul(0x100000001B3);
        (state >> 29) as u8
    }).collect()
}

fn cfb(key: &[u8], iv: &[u8], data: &[u8]) -> Vec<u8> {
    data.iter().enumerate().map(|(index, byte)| byte ^ key[(index * 7) % 32] ^ iv[index % iv.len()] ^ index as u8).collect()
}

struct Fake {
    next: AtomicU64,
    states: Mutex<HashMap<u64, (Vec<u8>, Vec<u8>)>>,
}

impl Provider for Fake {
    fn name(&self) -> &'static str {
        "fake"
    }

    fn release(&self, handle: ProviderHandle) {
        self.states.lock().unwrap().remove(&(handle.value as u64));
    }
}

impl SignatureProvider for Fake {
    fn supports(&self, request: &SignatureProviderRequest<'_>) -> bool {
        GOSTR3410::from_name(request.algorithm).is_some()
    }

    fn generate(&self, request: &SignatureProviderRequest<'_>) -> Result<(Vec<u8>, Vec<u8>), ProviderError> {
        let seed = request.seed.unwrap_or_default();
        Ok((seed.to_vec(), mix(&[b"public", seed], 64)))
    }

    fn public_key(&self, _request: &SignatureProviderRequest<'_>, _private: &[u8]) -> Result<Vec<u8>, ProviderError> {
        Err(ProviderError::Unsupported)
    }

    fn sign(&self, _request: &SignatureProviderRequest<'_>, _private: &[u8], _message: &[u8]) -> Result<Vec<u8>, ProviderError> {
        Err(ProviderError::Unsupported)
    }

    fn verify(&self, _request: &SignatureProviderRequest<'_>, _public: &[u8], _message: &[u8], _signature: &[u8]) -> Result<(), ProviderError> {
        Err(ProviderError::Unsupported)
    }
}

impl ExchangeProvider for Fake {
    fn supports(&self, request: &ExchangeProviderRequest<'_>) -> bool {
        request.algorithm.starts_with("VKO-")
    }

    fn generate(&self, _request: &ExchangeProviderRequest<'_>) -> Result<(Vec<u8>, Vec<u8>), ProviderError> {
        Err(ProviderError::Unsupported)
    }

    fn public_key(&self, _request: &ExchangeProviderRequest<'_>, _private: &[u8]) -> Result<Vec<u8>, ProviderError> {
        Err(ProviderError::Unsupported)
    }

    fn exchange(&self, request: &ExchangeProviderRequest<'_>, private: &[u8], peer: &[u8]) -> Result<Vec<u8>, ProviderError> {
        Ok(vko(request.algorithm, private, peer, request.context))
    }
}

impl HashProvider for Fake {
    fn supports(&self, request: &HashProviderRequest<'_>) -> bool {
        request.algorithm == HMACHash::Streebog256.as_str() && request.key.is_some()
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
        let length = digest.len().min(32);
        digest[..length].copy_from_slice(&hmac(&key, &data)[..length]);
        length
    }

    fn reset(&self, _handle: ProviderHandle) {}

    fn duplicate(&self, handle: ProviderHandle) -> ProviderHandle {
        handle
    }
}

impl CipherProvider for Fake {
    fn supports(&self, request: &CipherProviderRequest<'_>) -> bool {
        request.algorithm == GOST28147::name(GOST28147Mode::CFB, GOST28147SBox::TC26Z)
    }

    fn encrypt(&self, request: &CipherProviderRequest<'_>, plaintext: &[u8]) -> Result<Vec<u8>, ProviderError> {
        Ok(cfb(request.key, request.nonce, plaintext))
    }

    fn decrypt(&self, _request: &CipherProviderRequest<'_>, _ciphertext: &[u8]) -> Result<Vec<u8>, ProviderError> {
        Err(ProviderError::Unsupported)
    }
}

fn vko(algorithm: &str, private: &[u8], peer: &[u8], ukm: &[u8]) -> Vec<u8> {
    let size = if algorithm.starts_with("VKO-512-") { 64 } else { 32 };
    mix(&[algorithm.as_bytes(), private, peer, ukm], size)
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    mix(&[b"hmac", key, data], 32)
}

fn install() {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        let fake = Arc::new(Fake { next: AtomicU64::new(1), states: Mutex::new(HashMap::new()) });
        SignatureProviders::global().register(fake.clone()).unwrap();
        ExchangeProviders::global().register(fake.clone()).unwrap();
        HashProviders::global().register(fake.clone()).unwrap();
        CipherProviders::global().register(fake).unwrap();
    });
}

fn digest() -> [u8; 32] {
    core::array::from_fn(|index| (index as u8).wrapping_mul(37).wrapping_add(11))
}

#[test]
fn vko_512_is_only_defined_for_512_bit_keys_by_rfc7836() {
    let mut names = Vec::new();
    for variant in [GOSTR3410::GC256A, GOSTR3410::GC256B, GOSTR3410::GC256C, GOSTR3410::GC256D, GOSTR3410::GC512A, GOSTR3410::GC512B, GOSTR3410::GC512C] {
        names.push(variant.exchange_name(Streebog::V256).unwrap());
        match variant.coordinate_size() {
            32 => assert_eq!(variant.exchange_name(Streebog::V512), None, "{variant}"),
            _ => names.push(variant.exchange_name(Streebog::V512).unwrap()),
        }
    }
    let count = names.len();
    names.sort();
    names.dedup();
    assert_eq!(names.len(), count);
}

#[test]
fn keg_256_derives_export_keys_with_kdf_tree_by_rfc9189() {
    install();
    let (private, _) = GOSTR3410::GC256A.generate(b"server").unwrap();
    let (_, peer) = GOSTR3410::GC256A.generate(b"client").unwrap();
    let digest = digest();
    let ukm: Vec<u8> = digest[..16].iter().rev().copied().collect();
    let key = vko("VKO-256-GC256A", &private.encode(), &peer.encode(), &ukm);
    let block = |index: u8| hmac(&key, &[&[index][..], b"kdf tree", &[0x00], &digest[16..24], &[0x02, 0x00]].concat());
    let expected = [block(1), block(2)].concat();
    assert_eq!(private.keg(&peer, &digest).unwrap().as_slice(), expected.as_slice());
}

#[test]
fn keg_replaces_a_zero_ukm_with_one_by_rfc9189() {
    install();
    let (private, _) = GOSTR3410::GC256D.generate(b"server").unwrap();
    let (_, peer) = GOSTR3410::GC256D.generate(b"client").unwrap();
    let mut digest = digest();
    digest[..16].fill(0);
    let mut ukm = vec![0; 16];
    ukm[0] = 1;
    let key = vko("VKO-256-GC256D", &private.encode(), &peer.encode(), &ukm);
    let block = |index: u8| hmac(&key, &[&[index][..], b"kdf tree", &[0x00], &digest[16..24], &[0x02, 0x00]].concat());
    assert_eq!(private.keg(&peer, &digest).unwrap().as_slice(), [block(1), block(2)].concat().as_slice());
}

#[test]
fn keg_512_is_vko_512_by_rfc9189() {
    install();
    let (private, _) = GOSTR3410::GC512B.generate(b"server").unwrap();
    let (_, peer) = GOSTR3410::GC512B.generate(b"client").unwrap();
    let digest = digest();
    let ukm: Vec<u8> = digest[..16].iter().rev().copied().collect();
    let secret = private.keg(&peer, &digest).unwrap();
    assert_eq!(secret.len(), 64);
    assert_eq!(secret.as_slice(), vko("VKO-512-GC512B", &private.encode(), &peer.encode(), &ukm).as_slice());
}

#[test]
fn keg_28147_diversifies_vko_256_by_rfc9189_and_rfc4357() {
    install();
    let (private, _) = GOSTR3410::GC256B.generate(b"server").unwrap();
    let (_, peer) = GOSTR3410::GC256B.generate(b"client").unwrap();
    let digest = digest();
    let ukm = &digest[..8];
    let mut expected: [u8; 32] = vko("VKO-256-GC256B", &private.encode(), &peer.encode(), ukm).try_into().unwrap();
    for byte in ukm {
        let words: Vec<u32> = expected.chunks(4).map(|word| u32::from_le_bytes(word.try_into().unwrap())).collect();
        let s1 = (0..8).filter(|bit| (byte >> bit) & 1 == 1).fold(0u32, |sum, bit| sum.wrapping_add(words[bit]));
        let s2 = (0..8).filter(|bit| (byte >> bit) & 1 == 0).fold(0u32, |sum, bit| sum.wrapping_add(words[bit]));
        expected = cfb(&expected, &[s1.to_le_bytes(), s2.to_le_bytes()].concat(), &expected).try_into().unwrap();
    }
    assert_eq!(private.keg_28147(&peer, &digest, GOST28147SBox::TC26Z).unwrap().as_slice(), expected.as_slice());
}

#[test]
fn key_agreement_rejects_keys_on_different_curves() {
    install();
    let (private, _) = GOSTR3410::GC256A.generate(b"server").unwrap();
    let (_, peer) = GOSTR3410::GC256B.generate(b"client").unwrap();
    assert_eq!(private.keg(&peer, &digest()), Err(GOSTR3410Error::Curve));
    assert_eq!(private.exchange(&peer, &[1], Streebog::V256), Err(GOSTR3410Error::Curve));
    let (_, peer) = GOSTR3410::GC256A.generate(b"client").unwrap();
    assert_eq!(private.exchange(&peer, &[1], Streebog::V512), Err(GOSTR3410Error::Digest));
}

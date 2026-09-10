use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Once};

use umineko_crypto_hmac::HMACHash;
use umineko_helpers::provider::{HashProvider, HashProviderRequest, HashProviders, Provider, ProviderCategory, ProviderError, ProviderHandle};
use umineko_protocol_tls::TLSHash;
use umineko_protocol_tls::helpers::TLSPRF;

fn pseudorandom(algorithm: &str, key: &[u8], data: &[u8], size: usize) -> Vec<u8> {
    let mut state: u64 = 0xCBF29CE484222325;
    for byte in algorithm.bytes().chain(key.len().to_le_bytes()).chain(key.iter().copied()).chain(data.iter().copied()) {
        state = (state ^ byte as u64).wrapping_mul(0x100000001B3);
    }
    (0..size).map(|index| {
        state = (state ^ index as u64).wrapping_mul(0x100000001B3);
        (state >> 29) as u8
    }).collect()
}

struct Fake {
    next: AtomicU64,
    states: Mutex<HashMap<u64, (&'static str, Vec<u8>, Vec<u8>)>>,
}

impl Provider for Fake {
    fn name(&self) -> &'static str {
        "fake-hmac"
    }

    fn release(&self, handle: ProviderHandle) {
        self.states.lock().unwrap().remove(&(handle.value as u64));
    }
}

impl HashProvider for Fake {
    fn supports(&self, request: &HashProviderRequest<'_>) -> bool {
        request.key.is_some() && HMACHash::from_name(request.algorithm).is_some()
    }

    fn open(&self, request: &HashProviderRequest<'_>) -> Result<ProviderHandle, ProviderError> {
        let id = self.next.fetch_add(1, Ordering::SeqCst);
        self.states.lock().unwrap().insert(id, (request.algorithm, request.key.unwrap_or_default().to_vec(), Vec::new()));
        Ok(ProviderHandle::new(ProviderCategory::Hash, id as _))
    }

    fn update(&self, handle: ProviderHandle, data: &[u8]) {
        self.states.lock().unwrap().get_mut(&(handle.value as u64)).unwrap().2.extend_from_slice(data);
    }

    fn finalize(&self, handle: ProviderHandle, digest: &mut [u8]) -> usize {
        let (algorithm, key, data) = self.states.lock().unwrap().get(&(handle.value as u64)).unwrap().clone();
        let output = pseudorandom(algorithm, &key, &data, HMACHash::from_name(algorithm).unwrap().digest_size());
        let length = digest.len().min(output.len());
        digest[..length].copy_from_slice(&output[..length]);
        length
    }

    fn reset(&self, _handle: ProviderHandle) {}

    fn duplicate(&self, handle: ProviderHandle) -> ProviderHandle {
        handle
    }
}

fn install() {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| HashProviders::global().register(Arc::new(Fake { next: AtomicU64::new(1), states: Mutex::new(HashMap::new()) })).unwrap());
}

fn p_hash(hash: HMACHash, secret: &[u8], seed: &[u8], length: usize) -> Vec<u8> {
    let hmac = |data: &[u8]| pseudorandom(hash.as_str(), secret, data, hash.digest_size());
    let mut a = seed.to_vec();
    let mut output = Vec::new();
    while output.len() < length {
        a = hmac(&a);
        output.extend(hmac(&[a.as_slice(), seed].concat()));
    }
    output.truncate(length);
    output
}

#[test]
fn the_tls12_prf_is_p_hash_over_the_label_and_seed_by_rfc5246_and_rfc7836() {
    install();
    let secret: Vec<u8> = (0..48).collect();
    let seed: Vec<u8> = (100..164).collect();
    for (hash, hmac) in [(TLSHash::SHA256, HMACHash::SHA2_256), (TLSHash::SHA384, HMACHash::SHA2_384), (TLSHash::STREEBOG256, HMACHash::Streebog256)] {
        for length in [12, 48, 100, 104] {
            let mut output = vec![0; length];
            TLSPRF::new(hash).derive(&secret, b"key expansion", &seed, &mut output).unwrap();
            assert_eq!(output, p_hash(hmac, &secret, &[&b"key expansion"[..], &seed].concat(), length), "{hash} {length}");
        }
    }
}

#[test]
fn the_tls10_prf_xors_md5_and_sha1_over_overlapping_halves_by_rfc2246() {
    install();
    for secret_length in [0, 1, 47, 48] {
        for length in [12, 37, 48, 104] {
            let secret: Vec<u8> = (0..secret_length).map(|value| value as u8 ^ 0x5A).collect();
            let seed = [0x33; 64];
            let half = (secret_length as usize).div_ceil(2);
            let label_seed = [&b"master secret"[..], &seed].concat();
            let md5 = p_hash(HMACHash::MD5, &secret[..half], &label_seed, length);
            let sha1 = p_hash(HMACHash::SHA1, &secret[secret.len() - half..], &label_seed, length);
            let expected: Vec<u8> = md5.iter().zip(&sha1).map(|(left, right)| left ^ right).collect();
            let mut output = vec![0; length];
            TLSPRF::new(TLSHash::MD5_SHA1).derive(&secret, b"master secret", &seed, &mut output).unwrap();
            assert_eq!(output, expected, "{secret_length} {length}");
        }
    }
}

#[test]
fn prf_hashes_map_to_their_hmacs() {
    let expected = [
        (TLSHash::MD5_SHA1, None),
        (TLSHash::SHA256, Some(HMACHash::SHA2_256)),
        (TLSHash::SHA384, Some(HMACHash::SHA2_384)),
        (TLSHash::SHA512, Some(HMACHash::SHA2_512)),
        (TLSHash::SM3, Some(HMACHash::SM3)),
        (TLSHash::STREEBOG256, Some(HMACHash::Streebog256)),
        (TLSHash::ASCONHASH256, Some(HMACHash::AsconHash256)),
    ];
    assert_eq!(TLSHash::ALL.len(), expected.len());
    for (hash, hmac) in expected {
        assert_eq!(hash.hmac(), hmac, "{hash}");
        if let Some(hmac) = hmac {
            assert_eq!(hmac.digest_size(), hash.digest_size(), "{hash}");
        }
    }
}

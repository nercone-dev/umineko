use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Once};

use umineko_crypto_hmac::HMACHash;
use umineko_helpers::provider::{HashProvider, HashProviderRequest, HashProviders, Provider, ProviderCategory, ProviderError, ProviderHandle};
use umineko_protocol_tls::TLSCipher;
use umineko_protocol_tls::helpers::TLSTree;

fn pseudorandom(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut state: u64 = 0xCBF29CE484222325;
    for byte in key.iter().copied().chain(data.iter().copied()) {
        state = (state ^ byte as u64).wrapping_mul(0x100000001B3);
    }
    (0..32).map(|index: u64| {
        state = (state ^ index).wrapping_mul(0x100000001B3);
        (state >> 29) as u8
    }).collect()
}

struct Fake {
    next: AtomicU64,
    states: Mutex<HashMap<u64, (Vec<u8>, Vec<u8>)>>,
}

impl Provider for Fake {
    fn name(&self) -> &'static str {
        "fake-hmac-streebog"
    }

    fn release(&self, handle: ProviderHandle) {
        self.states.lock().unwrap().remove(&(handle.value as u64));
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
        let output = pseudorandom(&key, &data);
        let length = digest.len().min(32);
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

fn kdf_gostr3411_2012_256(key: &[u8], label: &[u8], seed: &[u8]) -> Vec<u8> {
    pseudorandom(key, &[&[0x01][..], label, &[0x00], seed, &[0x01, 0x00]].concat())
}

fn tlstree(root: &[u8], sequence: u64, constants: [u64; 3]) -> Vec<u8> {
    let level1 = kdf_gostr3411_2012_256(root, b"level1", &(sequence & constants[0]).to_be_bytes());
    let level2 = kdf_gostr3411_2012_256(&level1, b"level2", &(sequence & constants[1]).to_be_bytes());
    kdf_gostr3411_2012_256(&level2, b"level3", &(sequence & constants[2]).to_be_bytes())
}

const CONSTANTS: [(TLSCipher, [u64; 3]); 6] = [
    (TLSCipher::TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC, [0xFFFFFFFF00000000, 0xFFFFFFFFFFF80000, 0xFFFFFFFFFFFFFFC0]),
    (TLSCipher::TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC, [0xFFFFFFC000000000, 0xFFFFFFFFFE000000, 0xFFFFFFFFFFFFF000]),
    (TLSCipher::TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L, [0xF800000000000000, 0xFFFFFFF000000000, 0xFFFFFFFFFFFFE000]),
    (TLSCipher::TLS_GOSTR341112_256_WITH_MAGMA_MGM_L, [0xFFE0000000000000, 0xFFFFFFFFC0000000, 0xFFFFFFFFFFFFFF80]),
    (TLSCipher::TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S, [0xFFFFFFFFE0000000, 0xFFFFFFFFFFFF0000, 0xFFFFFFFFFFFFFFF8]),
    (TLSCipher::TLS_GOSTR341112_256_WITH_MAGMA_MGM_S, [0xFFFFFFFFFC000000, 0xFFFFFFFFFFFFE000, 0xFFFFFFFFFFFFFFFF]),
];

#[test]
fn key_tree_constants_follow_rfc9189_and_rfc9367() {
    for (cipher, constants) in CONSTANTS {
        assert_eq!(TLSTree::from_cipher(cipher).map(|tree| tree.constants()), Some(constants), "{cipher}");
    }
    for cipher in TLSCipher::ALL {
        if CONSTANTS.iter().all(|(other, _)| *other != cipher) {
            assert_eq!(TLSTree::from_cipher(cipher), None, "{cipher}");
        }
    }
}

#[test]
fn tlstree_chains_three_kdf_levels_over_masked_sequence_numbers_by_rfc9189() {
    install();
    let root: Vec<u8> = (0..32).collect();
    for (cipher, constants) in CONSTANTS {
        let tree = TLSTree::from_cipher(cipher).unwrap();
        for sequence in [0, 1, 63, 64, 4095, 4096, 0x0123_4567_89AB_CDEF, u64::MAX] {
            assert_eq!(tree.derive(root.as_slice().try_into().unwrap(), sequence).unwrap().to_vec(), tlstree(&root, sequence, constants), "{cipher} {sequence}");
        }
    }
}

#[test]
fn record_keys_only_change_at_level_three_boundaries() {
    install();
    let root = [0x5A; 32];
    let tree = TLSTree::from_cipher(TLSCipher::TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC).unwrap();
    assert_eq!(tree.derive(&root, 0).unwrap(), tree.derive(&root, 63).unwrap());
    assert_ne!(tree.derive(&root, 63).unwrap(), tree.derive(&root, 64).unwrap());
    let tree = TLSTree::from_cipher(TLSCipher::TLS_GOSTR341112_256_WITH_MAGMA_MGM_S).unwrap();
    assert_ne!(tree.derive(&root, 0).unwrap(), tree.derive(&root, 1).unwrap());
}

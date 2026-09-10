use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Once};

use umineko_crypto_hmac::HMACHash;
use umineko_crypto_kdftree::KDFTree;
use umineko_helpers::provider::{HashProvider, HashProviderRequest, HashProviders, Provider, ProviderCategory, ProviderError, ProviderHandle};

struct Recorder {
    next: AtomicU64,
    states: Mutex<HashMap<u64, (Vec<u8>, Vec<u8>)>>,
}

impl Provider for Recorder {
    fn name(&self) -> &'static str {
        "recorder"
    }

    fn release(&self, handle: ProviderHandle) {
        self.states.lock().unwrap().remove(&(handle.value as u64));
    }
}

impl HashProvider for Recorder {
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
        let output = prf(&key, &data);
        let length = digest.len().min(32);
        digest[..length].copy_from_slice(&output[..length]);
        length
    }

    fn reset(&self, _handle: ProviderHandle) {}

    fn duplicate(&self, handle: ProviderHandle) -> ProviderHandle {
        handle
    }
}

fn prf(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut state: u64 = 0xCBF29CE484222325;
    for byte in key.len().to_le_bytes().iter().chain(key).chain(data) {
        state = (state ^ *byte as u64).wrapping_mul(0x100000001B3);
    }
    (0..32).map(|index: u64| {
        state = (state ^ index).wrapping_mul(0x100000001B3);
        (state >> 29) as u8
    }).collect()
}

fn install() {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| HashProviders::global().register(Arc::new(Recorder { next: AtomicU64::new(1), states: Mutex::new(HashMap::new()) })).unwrap());
}

fn kdf_tree(key: &[u8], label: &[u8], seed: &[u8], counter_size: usize, length: usize) -> Vec<u8> {
    let bits = (length as u64 * 8).to_be_bytes();
    let bits = &bits[bits.iter().take_while(|byte| **byte == 0).count()..];
    let mut output = Vec::new();
    let mut index: u32 = 1;
    while output.len() < length {
        let counter = index.to_be_bytes();
        output.extend(prf(key, &[&counter[4 - counter_size..], label, &[0x00], seed, bits].concat()));
        index += 1;
    }
    output.truncate(length);
    output
}

#[test]
fn the_builtin_derivation_concatenates_prf_blocks_by_rfc7836() {
    install();
    let key = [0x42; 32];
    let seed = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    for (counter_size, length) in [(1, 32), (1, 40), (1, 64), (2, 100), (4, 33)] {
        let mut output = vec![0; length];
        KDFTree::new(HMACHash::Streebog256, counter_size).unwrap().derive(&key, b"kdf tree", &seed, &mut output).unwrap();
        assert_eq!(output, kdf_tree(&key, b"kdf tree", &seed, counter_size, length), "{counter_size} {length}");
    }
}

#[test]
fn the_maximum_output_length_is_accepted_by_rfc7836() {
    install();
    let mut output = vec![0; 255 * 32];
    KDFTree::new(HMACHash::Streebog256, 1).unwrap().derive(&[0x24; 32], b"label", b"seed", &mut output).unwrap();
    assert_eq!(output, kdf_tree(&[0x24; 32], b"label", b"seed", 1, 255 * 32));
}

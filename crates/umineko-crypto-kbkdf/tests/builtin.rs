use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Once};

use umineko_crypto_hmac::HMACHash;
use umineko_crypto_kbkdf::{KBKDF, KBKDFMode};
use umineko_helpers::provider::{HashProvider, HashProviderRequest, HashProviders, Provider, ProviderCategory, ProviderError, ProviderHandle};

const KEY: [u8; 32] = [0x42; 32];

struct Recorder {
    next: AtomicU64,
    states: Mutex<HashMap<u64, (Vec<u8>, Vec<u8>)>>,
}

impl Provider for Recorder {
    fn name(&self) -> &'static str {
        "recorder"
    }

    fn release(&self, handle: ProviderHandle) {
        self.states.lock().unwrap().remove(&handle.value);
    }
}

impl HashProvider for Recorder {
    fn supports(&self, request: &HashProviderRequest<'_>) -> bool {
        request.algorithm == HMACHash::SHA2_256.as_str() && request.key.is_some()
    }

    fn open(&self, request: &HashProviderRequest<'_>) -> Result<ProviderHandle, ProviderError> {
        let id = self.next.fetch_add(1, Ordering::SeqCst);
        self.states.lock().unwrap().insert(id, (request.key.unwrap_or_default().to_vec(), Vec::new()));
        Ok(ProviderHandle::new(ProviderCategory::Hash, id))
    }

    fn update(&self, handle: ProviderHandle, data: &[u8]) {
        self.states.lock().unwrap().get_mut(&handle.value).unwrap().1.extend_from_slice(data);
    }

    fn finalize(&self, handle: ProviderHandle, digest: &mut [u8]) -> usize {
        let (key, data) = self.states.lock().unwrap().get(&handle.value).unwrap().clone();
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

fn fixed(label: &[u8], context: &[u8], length: usize) -> Vec<u8> {
    [label, &[0x00], context, &((length * 8) as u32).to_be_bytes()].concat()
}

fn counter(index: u32, counter_size: Option<usize>) -> Vec<u8> {
    counter_size.map(|size| index.to_be_bytes()[4 - size..].to_vec()).unwrap_or_default()
}

fn counter_mode(label: &[u8], context: &[u8], counter_size: usize, length: usize) -> Vec<u8> {
    let fixed = fixed(label, context, length);
    let mut output = Vec::new();
    let mut index = 1;
    while output.len() < length {
        output.extend(prf(&KEY, &[&counter(index, Some(counter_size))[..], &fixed].concat()));
        index += 1;
    }
    output.truncate(length);
    output
}

fn feedback_mode(label: &[u8], context: &[u8], iv: &[u8], counter_size: Option<usize>, length: usize) -> Vec<u8> {
    let fixed = fixed(label, context, length);
    let mut previous = iv.to_vec();
    let mut output = Vec::new();
    let mut index = 1;
    while output.len() < length {
        previous = prf(&KEY, &[&previous[..], &counter(index, counter_size), &fixed].concat());
        output.extend_from_slice(&previous);
        index += 1;
    }
    output.truncate(length);
    output
}

fn double_pipeline_mode(label: &[u8], context: &[u8], counter_size: Option<usize>, length: usize) -> Vec<u8> {
    let fixed = fixed(label, context, length);
    let mut pipeline = fixed.clone();
    let mut output = Vec::new();
    let mut index = 1;
    while output.len() < length {
        pipeline = prf(&KEY, &pipeline);
        output.extend(prf(&KEY, &[&pipeline[..], &counter(index, counter_size), &fixed].concat()));
        index += 1;
    }
    output.truncate(length);
    output
}

#[test]
fn counter_mode_concatenates_prf_blocks_by_sp800_108r1() {
    install();
    for (counter_size, length) in [(1, 32), (2, 33), (4, 64), (4, 100)] {
        let mut output = vec![0; length];
        KBKDF::new(HMACHash::SHA2_256, KBKDFMode::Counter, Some(counter_size), 4).unwrap().derive(&KEY, b"label", b"context", &[], &mut output).unwrap();
        assert_eq!(output, counter_mode(b"label", b"context", counter_size, length), "{counter_size} {length}");
    }
}

#[test]
fn feedback_mode_chains_prf_blocks_from_the_iv_by_sp800_108r1() {
    install();
    for counter_size in [None, Some(1), Some(4)] {
        for iv in [&[][..], &[0x5A; 32][..]] {
            for length in [32, 65] {
                let mut output = vec![0; length];
                KBKDF::new(HMACHash::SHA2_256, KBKDFMode::Feedback, counter_size, 4).unwrap().derive(&KEY, b"label", b"context", iv, &mut output).unwrap();
                assert_eq!(output, feedback_mode(b"label", b"context", iv, counter_size, length), "{counter_size:?} {} {length}", iv.len());
            }
        }
    }
}

#[test]
fn double_pipeline_mode_iterates_the_fixed_input_by_sp800_108r1() {
    install();
    for counter_size in [None, Some(2)] {
        for length in [31, 96] {
            let mut output = vec![0; length];
            KBKDF::new(HMACHash::SHA2_256, KBKDFMode::DoublePipeline, counter_size, 4).unwrap().derive(&KEY, b"label", b"context", &[], &mut output).unwrap();
            assert_eq!(output, double_pipeline_mode(b"label", b"context", counter_size, length), "{counter_size:?} {length}");
        }
    }
}

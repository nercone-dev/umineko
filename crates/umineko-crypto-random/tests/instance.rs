use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Once};

use umineko_crypto_random::{DRBG, DRBGCipher, DRBGHash, RandomError};
use umineko_helpers::provider::{Provider, ProviderCategory, ProviderError, ProviderHandle, RandomProvider, RandomProviderRequest, RandomProviders};

struct Recorder {
    next: AtomicU64,
    strengths: Mutex<Vec<Option<usize>>>,
}

impl Provider for Recorder {
    fn name(&self) -> &'static str {
        "recorder"
    }

    fn release(&self, _handle: ProviderHandle) {}
}

impl RandomProvider for Recorder {
    fn supports(&self, _request: &RandomProviderRequest<'_>) -> bool {
        true
    }

    fn open(&self, request: &RandomProviderRequest<'_>) -> Result<ProviderHandle, ProviderError> {
        self.strengths.lock().unwrap().push(request.security_strength);
        Ok(ProviderHandle::new(ProviderCategory::Random, self.next.fetch_add(1, Ordering::SeqCst)))
    }

    fn reseed(&self, _handle: ProviderHandle, _entropy: &[u8], _additional: &[u8]) -> Result<(), ProviderError> {
        Ok(())
    }

    fn generate(&self, _handle: ProviderHandle, output: &mut [u8], _additional: &[u8]) -> Result<(), ProviderError> {
        output.fill(0x5A);
        Ok(())
    }
}

fn install() -> &'static Recorder {
    static INSTALL: Once = Once::new();
    static RECORDER: std::sync::OnceLock<Arc<Recorder>> = std::sync::OnceLock::new();
    let recorder = RECORDER.get_or_init(|| Arc::new(Recorder { next: AtomicU64::new(1), strengths: Mutex::new(Vec::new()) }));
    INSTALL.call_once(|| RandomProviders::global().register(recorder.clone()).unwrap());
    recorder
}

#[test]
fn the_security_strength_is_rounded_up_to_an_approved_strength_by_sp800_90a_section9_1() {
    let recorder = install();
    for (requested, expected) in [(1, 112), (112, 112), (113, 128), (150, 192), (192, 192), (200, 256), (256, 256)] {
        let instance = DRBG::HMAC(DRBGHash::SHA2_512).instantiate(&[0; 64], &[0; 32], b"personalization", requested, false).unwrap();
        assert_eq!(instance.security_strength(), expected, "{requested}");
        assert_eq!(recorder.strengths.lock().unwrap().last(), Some(&Some(expected)), "{requested}");
    }
}

#[test]
fn the_reseed_counter_starts_at_one_and_counts_requests_by_sp800_90a_section10() {
    install();
    let mut instance = DRBG::Hash(DRBGHash::SHA2_256).instantiate(&[0; 32], &[0; 16], &[], 256, false).unwrap();
    assert_eq!(instance.counter(), 1);
    assert!(!instance.reseed_required());
    let mut output = [0; 32];
    instance.generate(&mut output, b"additional").unwrap();
    assert_eq!(output, [0x5A; 32]);
    instance.generate(&mut output, &[]).unwrap();
    assert_eq!(instance.counter(), 3);
    instance.reseed(&[0; 32], &[]).unwrap();
    assert_eq!(instance.counter(), 1);
    assert_eq!(instance.reseed(&[0; 31], &[]), Err(RandomError::Entropy));
}

#[test]
fn requests_are_bounded_by_sp800_90a_tables_2_and_3() {
    install();
    let mut instance = DRBG::Hash(DRBGHash::SHA2_256).instantiate(&[0; 32], &[0; 16], &[], 256, false).unwrap();
    assert_eq!(instance.generate(&mut vec![0; (1 << 16) + 1], &[]), Err(RandomError::Request));
    assert_eq!(instance.counter(), 1);
    assert_eq!(instance.generate(&mut vec![0; 1 << 16], &[]), Ok(()));
    let mut instance = DRBG::CTR { cipher: DRBGCipher::TDEA, derivation: false }.instantiate(&[0; 29], &[], &[], 112, true).unwrap();
    assert!(instance.prediction_resistance());
    assert_eq!(instance.generate(&mut [0; 1025], &[]), Err(RandomError::Request));
    assert_eq!(instance.generate(&mut [0; 1024], &[0; 30]), Err(RandomError::Additional));
    assert_eq!(instance.generate(&mut [0; 1024], &[0; 29]), Ok(()));
    assert_eq!(instance.reseed(&[0; 28], &[]), Err(RandomError::Entropy));
    assert_eq!(instance.reseed(&[0; 30], &[]), Err(RandomError::Entropy));
    assert_eq!(instance.reseed(&[0; 29], &[0; 30]), Err(RandomError::Additional));
    assert_eq!(instance.reseed(&[0; 29], &[0; 29]), Ok(()));
}

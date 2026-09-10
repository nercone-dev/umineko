use std::sync::Arc;

use umineko_crypto_hmac::{HMAC, HMACError, HMACHash};
use umineko_helpers::provider::{HashProvider, HashProviderRequest, HashProviders, Provider, ProviderCategory, ProviderError, ProviderHandle};

struct Fixed;

impl Provider for Fixed {
    fn name(&self) -> &'static str {
        "fixed"
    }

    fn release(&self, _handle: ProviderHandle) {}
}

impl HashProvider for Fixed {
    fn supports(&self, request: &HashProviderRequest<'_>) -> bool {
        request.algorithm == HMACHash::SHA2_256.as_str()
    }

    fn open(&self, _request: &HashProviderRequest<'_>) -> Result<ProviderHandle, ProviderError> {
        Ok(ProviderHandle::new(ProviderCategory::Hash, 1))
    }

    fn update(&self, _handle: ProviderHandle, _data: &[u8]) {}

    fn finalize(&self, _handle: ProviderHandle, digest: &mut [u8]) -> usize {
        let length = digest.len().min(32);
        digest[..length].fill(0xAB);
        length
    }

    fn reset(&self, _handle: ProviderHandle) {}

    fn duplicate(&self, handle: ProviderHandle) -> ProviderHandle {
        handle
    }
}

#[test]
fn verification_rejects_tags_that_are_too_short_too_long_or_wrong() {
    HashProviders::global().register(Arc::new(Fixed)).unwrap();
    let verify = |tag: &[u8]| HMAC::new(HMACHash::SHA2_256, b"key").verify(tag);
    assert_eq!(verify(&[0xAB; 32]), Ok(()));
    assert_eq!(verify(&[0xAB; 16]), Ok(()));
    assert_eq!(verify(&[0xAB; 15]), Err(HMACError::Length));
    assert_eq!(verify(&[0xAB; 1]), Err(HMACError::Length));
    assert_eq!(verify(&[]), Err(HMACError::Length));
    assert_eq!(verify(&[0xAB; 33]), Err(HMACError::Length));
    let mut wrong = [0xAB; 32];
    wrong[31] = 0xAC;
    assert_eq!(verify(&wrong), Err(HMACError::Authentication));
}

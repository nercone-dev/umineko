use std::sync::Arc;

use umineko_crypto_cmac::{CMAC, CMACCipher, CMACError};
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
        request.algorithm == CMACCipher::AES128.as_str()
    }

    fn open(&self, _request: &HashProviderRequest<'_>) -> Result<ProviderHandle, ProviderError> {
        Ok(ProviderHandle::new(ProviderCategory::Hash, 1))
    }

    fn update(&self, _handle: ProviderHandle, _data: &[u8]) {}

    fn finalize(&self, _handle: ProviderHandle, digest: &mut [u8]) -> usize {
        let length = digest.len().min(16);
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
    let verify = |tag: &[u8]| CMAC::new(CMACCipher::AES128, &[0x2B; 16]).unwrap().verify(tag);
    assert_eq!(verify(&[0xAB; 16]), Ok(()));
    assert_eq!(verify(&[0xAB; 8]), Ok(()));
    assert_eq!(verify(&[0xAB; 7]), Err(CMACError::Length));
    assert_eq!(verify(&[]), Err(CMACError::Length));
    assert_eq!(verify(&[0xAB; 17]), Err(CMACError::Length));
    let mut wrong = [0xAB; 16];
    wrong[15] = 0xAC;
    assert_eq!(verify(&wrong), Err(CMACError::Authentication));
    let mut tag = [0; 16];
    assert_eq!(CMAC::tag(CMACCipher::AES128, &[0x2B; 16], b"data", &mut tag), Ok(16));
    assert_eq!(tag, [0xAB; 16]);
}

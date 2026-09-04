use umineko_provider::{HashProvider, HashProviderRequest, ProviderError, ProviderHandle};
use crate::freebsd::FreeBSDProvider;

impl HashProvider for FreeBSDProvider {
    fn supports(&self, request: &HashProviderRequest<'_>) -> bool {
        let _ = request;
        false
    }

    fn open(&self, request: &HashProviderRequest<'_>) -> Result<ProviderHandle, ProviderError> {
        todo!()
    }

    fn update(&self, handle: ProviderHandle, data: &[u8]) {
        todo!()
    }

    fn finalize(&self, handle: ProviderHandle, digest: &mut [u8]) -> usize {
        todo!()
    }

    fn reset(&self, handle: ProviderHandle) {
        todo!()
    }

    fn duplicate(&self, handle: ProviderHandle) -> ProviderHandle {
        todo!()
    }
}

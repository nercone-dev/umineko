use std::sync::Arc;

use umineko_provider::{HashProvider, HashProviderRequest, HashProviders, Provider, ProviderBundle, ProviderCategory, ProviderError, ProviderFallback, ProviderHandle, ProviderInterest, ProviderOrder, ProviderPolicy, Providers, TCPProvider, TCPProviderRequest, TCPProviders};
use umineko_protocol_tcp::{TCPEndpoint, TCPState};

struct Fake;

impl Provider for Fake {
    fn name(&self) -> &'static str {
        "fake"
    }

    fn priority(&self) -> i32 {
        7
    }

    fn release(&self, _handle: ProviderHandle) {}
}

impl HashProvider for Fake {
    fn supports(&self, request: &HashProviderRequest<'_>) -> bool {
        request.algorithm == "SHA-256"
    }

    fn open(&self, _request: &HashProviderRequest<'_>) -> Result<ProviderHandle, ProviderError> {
        Ok(ProviderHandle::new(ProviderCategory::Hash, 1))
    }

    fn update(&self, _handle: ProviderHandle, _data: &[u8]) {}

    fn finalize(&self, _handle: ProviderHandle, digest: &mut [u8]) -> usize {
        digest.fill(0xAB);
        digest.len()
    }

    fn reset(&self, _handle: ProviderHandle) {}

    fn duplicate(&self, handle: ProviderHandle) -> ProviderHandle {
        handle
    }
}

impl TCPProvider for Fake {
    fn supports(&self, _request: &TCPProviderRequest<'_>) -> bool {
        false
    }

    fn open(&self, _request: &TCPProviderRequest<'_>) -> Result<ProviderHandle, ProviderError> {
        Err(ProviderError::Unsupported)
    }

    fn poll_ready(&self, _handle: ProviderHandle, _interest: ProviderInterest, _cx: &mut core::task::Context<'_>) -> core::task::Poll<Result<(), ProviderError>> {
        core::task::Poll::Ready(Err(ProviderError::Unsupported))
    }

    fn accept(&self, _handle: ProviderHandle) -> Result<ProviderHandle, ProviderError> {
        Err(ProviderError::Unsupported)
    }

    fn send(&self, _handle: ProviderHandle, _data: &[u8]) -> Result<usize, ProviderError> {
        Err(ProviderError::Unsupported)
    }

    fn receive(&self, _handle: ProviderHandle, _data: &mut [u8]) -> Result<usize, ProviderError> {
        Err(ProviderError::Unsupported)
    }

    fn shutdown(&self, _handle: ProviderHandle) -> Result<(), ProviderError> {
        Err(ProviderError::Unsupported)
    }

    fn reset(&self, _handle: ProviderHandle) -> Result<(), ProviderError> {
        Err(ProviderError::Unsupported)
    }

    fn close(&self, _handle: ProviderHandle) -> Result<(), ProviderError> {
        Err(ProviderError::Unsupported)
    }

    fn set_no_delay(&self, _handle: ProviderHandle, _no_delay: bool) -> Result<(), ProviderError> {
        Err(ProviderError::Unsupported)
    }

    fn set_keepalive(&self, _handle: ProviderHandle, _keepalive: bool) -> Result<(), ProviderError> {
        Err(ProviderError::Unsupported)
    }

    fn local(&self, _handle: ProviderHandle) -> Result<TCPEndpoint, ProviderError> {
        Err(ProviderError::Unsupported)
    }

    fn remote(&self, _handle: ProviderHandle) -> Result<TCPEndpoint, ProviderError> {
        Err(ProviderError::Unsupported)
    }

    fn state(&self, _handle: ProviderHandle) -> Result<TCPState, ProviderError> {
        Err(ProviderError::Unsupported)
    }

    fn segment_size(&self, _handle: ProviderHandle) -> Result<u16, ProviderError> {
        Err(ProviderError::Unsupported)
    }
}

impl ProviderBundle for Fake {
    fn hash(self: Arc<Self>) -> Option<Arc<dyn HashProvider>> {
        Some(self)
    }

    fn tcp(self: Arc<Self>) -> Option<Arc<dyn TCPProvider>> {
        Some(self)
    }
}

#[test]
fn bundle_registration_reaches_exactly_the_declared_categories() {
    assert_eq!(Providers::register(Arc::new(Fake)), Ok(()));
    assert_eq!(Providers::register(Arc::new(Fake)), Err(ProviderError::Argument));
    assert!(Providers::registered("fake"));
    assert!(Providers::names().contains(&"fake"));
    assert!(Providers::available(ProviderCategory::Hash));
    assert!(Providers::available(ProviderCategory::TCP));
    assert!(!Providers::available(ProviderCategory::UDP));
    assert!(HashProviders::global().get("fake").is_some());
    assert!(TCPProviders::global().get("fake").is_some());
    assert_eq!(Providers::priority("fake"), Some(7));

    let mut digest = [0; 32];
    assert_eq!(HashProviders::digest(&HashProviderRequest::new("SHA-256"), b"", &mut digest), Some(32));
    assert_eq!(digest, [0xAB; 32]);
    assert_eq!(HashProviders::digest(&HashProviderRequest::new("SHA-512"), b"", &mut digest), None);

    assert!(Providers::set_enabled("fake", false));
    assert_eq!(Providers::enabled("fake"), Some(false));
    assert_eq!(HashProviders::digest(&HashProviderRequest::new("SHA-256"), b"", &mut digest), None);
    assert!(Providers::set_enabled("fake", true));

    let policy = ProviderPolicy { order: ProviderOrder::Explicit(vec!["fake".into()]), fallback: ProviderFallback::Any };
    Providers::set_policy(policy.clone());
    assert_eq!(Providers::policy(ProviderCategory::Hash), policy);
    assert_eq!(Providers::policy(ProviderCategory::UDP), policy);
    assert!(Providers::set_category_policy(ProviderCategory::Hash, ProviderPolicy::DEFAULT));
    assert_eq!(Providers::policy(ProviderCategory::Hash), ProviderPolicy::DEFAULT);
    assert_eq!(Providers::policy(ProviderCategory::TCP), policy);
    Providers::set_policy(ProviderPolicy::DEFAULT);

    assert!(Providers::unregister("fake"));
    assert!(!Providers::unregister("fake"));
    assert!(!Providers::registered("fake"));
    assert!(HashProviders::global().get("fake").is_none());
    assert!(TCPProviders::global().get("fake").is_none());
}

use alloc::sync::Arc;

use umineko_provider::{Provider, ProviderBundle, ProviderError, ProviderHandle};
use umineko_provider_posix::POSIXProvider;
#[cfg(feature = "ip")]
use umineko_provider::IPProvider;
#[cfg(feature = "icmp")]
use umineko_provider::ICMPProvider;
#[cfg(feature = "uds")]
use umineko_provider::UDSProvider;
#[cfg(feature = "tcp")]
use umineko_provider::TCPProvider;
#[cfg(feature = "udp")]
use umineko_provider::UDPProvider;
#[cfg(feature = "crypto")]
use umineko_provider::CipherProvider;
#[cfg(feature = "crypto")]
use umineko_provider::SignatureProvider;
#[cfg(feature = "crypto")]
use umineko_provider::ExchangeProvider;
#[cfg(feature = "crypto")]
use umineko_provider::KDFProvider;

#[derive(Debug, Default)]
pub struct AndroidProvider;

impl AndroidProvider {
    pub const NAME: &'static str = "android";

    pub fn new() -> Self {
        Self
    }

    pub fn available() -> bool {
        true
    }

    pub fn error(code: i32) -> ProviderError {
        POSIXProvider::error(code)
    }
}

impl Provider for AndroidProvider {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn release(&self, handle: ProviderHandle) {
        if POSIXProvider::provides(handle.category) {
            POSIXProvider.release(handle);
        }
    }
}

impl ProviderBundle for AndroidProvider {
    #[cfg(feature = "ip")]
    fn ip(self: Arc<Self>) -> Option<Arc<dyn IPProvider>> {
        Some(self)
    }

    #[cfg(feature = "icmp")]
    fn icmp(self: Arc<Self>) -> Option<Arc<dyn ICMPProvider>> {
        Some(self)
    }

    #[cfg(feature = "uds")]
    fn uds(self: Arc<Self>) -> Option<Arc<dyn UDSProvider>> {
        Some(self)
    }

    #[cfg(feature = "tcp")]
    fn tcp(self: Arc<Self>) -> Option<Arc<dyn TCPProvider>> {
        Some(self)
    }

    #[cfg(feature = "udp")]
    fn udp(self: Arc<Self>) -> Option<Arc<dyn UDPProvider>> {
        Some(self)
    }

    #[cfg(feature = "crypto")]
    fn cipher(self: Arc<Self>) -> Option<Arc<dyn CipherProvider>> {
        Some(self)
    }

    #[cfg(feature = "crypto")]
    fn signature(self: Arc<Self>) -> Option<Arc<dyn SignatureProvider>> {
        Some(self)
    }

    #[cfg(feature = "crypto")]
    fn exchange(self: Arc<Self>) -> Option<Arc<dyn ExchangeProvider>> {
        Some(self)
    }

    #[cfg(feature = "crypto")]
    fn kdf(self: Arc<Self>) -> Option<Arc<dyn KDFProvider>> {
        Some(self)
    }
}

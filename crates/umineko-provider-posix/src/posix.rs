use alloc::sync::Arc;

use umineko_provider::{Provider, ProviderBundle, ProviderCategory, ProviderError, ProviderHandle};
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
use crate::errno::POSIXErrno;

#[derive(Debug, Default)]
pub struct POSIXProvider;

impl POSIXProvider {
    pub const NAME: &'static str = "posix";

    pub fn new() -> Self {
        Self
    }

    pub fn available() -> bool {
        true
    }

    pub fn provides(category: ProviderCategory) -> bool {
        match category {
            ProviderCategory::IP => cfg!(feature = "ip"),
            ProviderCategory::ICMP => cfg!(feature = "icmp"),
            ProviderCategory::UDS => cfg!(feature = "uds"),
            ProviderCategory::TCP => cfg!(feature = "tcp"),
            ProviderCategory::UDP => cfg!(feature = "udp"),
            _ => false,
        }
    }

    pub fn error(code: i32) -> ProviderError {
        match POSIXErrno::from_number(code) {
            Some(errno) => errno.error(),
            None => ProviderError::System(code),
        }
    }
}

impl Provider for POSIXProvider {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn release(&self, handle: ProviderHandle) {
        let _ = handle;
    }
}

impl ProviderBundle for POSIXProvider {
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
}

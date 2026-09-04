use alloc::sync::Arc;

use umineko_provider::{Provider, ProviderBundle, ProviderError, ProviderHandle};
#[cfg(feature = "tcp")]
use umineko_provider::TCPProvider;
#[cfg(feature = "udp")]
use umineko_provider::UDPProvider;
#[cfg(feature = "http")]
use umineko_provider::HTTPProvider;

#[derive(Debug, Default)]
pub struct WASIProvider;

impl WASIProvider {
    pub const NAME: &'static str = "wasi";

    pub fn new() -> Self {
        Self
    }

    pub fn available() -> bool {
        true
    }

    pub fn error(code: i32) -> ProviderError {
        match code {
            2 | 63 => ProviderError::Permission,
            6 => ProviderError::WouldBlock,
            27 => ProviderError::Interrupted,
            28 => ProviderError::Argument,
            33 | 41 | 48 => ProviderError::Exhausted,
            52 | 58 => ProviderError::Unsupported,
            54 | 68 => ProviderError::Closed,
            73 => ProviderError::Timeout,
            other => ProviderError::System(other),
        }
    }
}

impl Provider for WASIProvider {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn release(&self, handle: ProviderHandle) {
        let _ = handle;
    }
}

impl ProviderBundle for WASIProvider {
    #[cfg(feature = "tcp")]
    fn tcp(self: Arc<Self>) -> Option<Arc<dyn TCPProvider>> {
        Some(self)
    }

    #[cfg(feature = "udp")]
    fn udp(self: Arc<Self>) -> Option<Arc<dyn UDPProvider>> {
        Some(self)
    }

    #[cfg(feature = "http")]
    fn http(self: Arc<Self>) -> Option<Arc<dyn HTTPProvider>> {
        Some(self)
    }
}

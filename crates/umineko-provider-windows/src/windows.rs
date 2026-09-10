use alloc::sync::Arc;

use umineko_provider::{Provider, ProviderBundle, ProviderError, ProviderHandle};
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
#[cfg(feature = "hash")]
use umineko_provider::HashProvider;
#[cfg(feature = "crypto")]
use umineko_provider::CipherProvider;
#[cfg(feature = "crypto")]
use umineko_provider::SignatureProvider;
#[cfg(feature = "crypto")]
use umineko_provider::ExchangeProvider;
#[cfg(feature = "crypto")]
use umineko_provider::KDFProvider;
#[cfg(feature = "tls")]
use umineko_provider::TLSProvider;
#[cfg(feature = "quic")]
use umineko_provider::QUICProvider;

#[derive(Debug, Default)]
pub struct WindowsProvider;

impl WindowsProvider {
    pub const NAME: &'static str = "windows";

    pub fn new() -> Self {
        Self
    }

    pub fn available() -> bool {
        true
    }

    pub fn error(code: i32) -> ProviderError {
        match code {
            5 => ProviderError::Permission,
            8 | 10055 => ProviderError::Exhausted,
            87 | 10022 => ProviderError::Argument,
            50 | 10045 => ProviderError::Unsupported,
            10004 => ProviderError::Interrupted,
            10035 => ProviderError::WouldBlock,
            10054 | 10058 => ProviderError::Closed,
            10060 => ProviderError::Timeout,
            other => ProviderError::System(other),
        }
    }
}

impl Provider for WindowsProvider {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn release(&self, handle: ProviderHandle) {
        let _ = handle;
    }
}

impl ProviderBundle for WindowsProvider {
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

    #[cfg(feature = "hash")]
    fn hash(self: Arc<Self>) -> Option<Arc<dyn HashProvider>> {
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

    #[cfg(feature = "tls")]
    fn tls(self: Arc<Self>) -> Option<Arc<dyn TLSProvider>> {
        Some(self)
    }

    #[cfg(feature = "quic")]
    fn quic(self: Arc<Self>) -> Option<Arc<dyn QUICProvider>> {
        Some(self)
    }
}

use alloc::sync::Arc;

use umineko_helpers::provider::Provider;
#[cfg(feature = "ip")]
use umineko_protocol_ip::IPProvider;
#[cfg(feature = "icmp")]
use umineko_protocol_icmp::ICMPProvider;
#[cfg(feature = "uds")]
use umineko_protocol_uds::UDSProvider;
#[cfg(feature = "tcp")]
use umineko_protocol_tcp::TCPProvider;
#[cfg(feature = "udp")]
use umineko_protocol_udp::UDPProvider;
#[cfg(feature = "tls")]
use umineko_protocol_tls::TLSProvider;
#[cfg(feature = "quic")]
use umineko_protocol_quic::QUICProvider;
#[cfg(feature = "http")]
use umineko_protocol_http::HTTPProvider;
#[cfg(feature = "dns")]
use umineko_protocol_dns::DNSProvider;
#[cfg(feature = "hash")]
use umineko_helpers::provider::HashProvider;
#[cfg(feature = "crypto")]
use umineko_helpers::provider::CipherProvider;
#[cfg(feature = "crypto")]
use umineko_helpers::provider::SignatureProvider;
#[cfg(feature = "crypto")]
use umineko_helpers::provider::ExchangeProvider;
#[cfg(feature = "crypto")]
use umineko_helpers::provider::KDFProvider;
#[cfg(feature = "codec")]
use umineko_helpers::provider::CodecProvider;

pub trait ProviderBundle: Provider {
    #[cfg(feature = "ip")]
    fn ip(self: Arc<Self>) -> Option<Arc<dyn IPProvider>> {
        None
    }

    #[cfg(feature = "icmp")]
    fn icmp(self: Arc<Self>) -> Option<Arc<dyn ICMPProvider>> {
        None
    }

    #[cfg(feature = "uds")]
    fn uds(self: Arc<Self>) -> Option<Arc<dyn UDSProvider>> {
        None
    }

    #[cfg(feature = "tcp")]
    fn tcp(self: Arc<Self>) -> Option<Arc<dyn TCPProvider>> {
        None
    }

    #[cfg(feature = "udp")]
    fn udp(self: Arc<Self>) -> Option<Arc<dyn UDPProvider>> {
        None
    }

    #[cfg(feature = "tls")]
    fn tls(self: Arc<Self>) -> Option<Arc<dyn TLSProvider>> {
        None
    }

    #[cfg(feature = "quic")]
    fn quic(self: Arc<Self>) -> Option<Arc<dyn QUICProvider>> {
        None
    }

    #[cfg(feature = "http")]
    fn http(self: Arc<Self>) -> Option<Arc<dyn HTTPProvider>> {
        None
    }

    #[cfg(feature = "dns")]
    fn dns(self: Arc<Self>) -> Option<Arc<dyn DNSProvider>> {
        None
    }

    #[cfg(feature = "hash")]
    fn hash(self: Arc<Self>) -> Option<Arc<dyn HashProvider>> {
        None
    }

    #[cfg(feature = "crypto")]
    fn cipher(self: Arc<Self>) -> Option<Arc<dyn CipherProvider>> {
        None
    }

    #[cfg(feature = "crypto")]
    fn signature(self: Arc<Self>) -> Option<Arc<dyn SignatureProvider>> {
        None
    }

    #[cfg(feature = "crypto")]
    fn exchange(self: Arc<Self>) -> Option<Arc<dyn ExchangeProvider>> {
        None
    }

    #[cfg(feature = "crypto")]
    fn kdf(self: Arc<Self>) -> Option<Arc<dyn KDFProvider>> {
        None
    }

    #[cfg(feature = "codec")]
    fn codec(self: Arc<Self>) -> Option<Arc<dyn CodecProvider>> {
        None
    }
}

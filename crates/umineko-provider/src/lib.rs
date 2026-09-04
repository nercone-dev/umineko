//! Provider contracts and registration.

#![no_std]

extern crate alloc;

pub mod bundle;
pub mod providers;

pub use umineko_helpers::provider::{Provider, ProviderCategory, ProviderHandle, ProviderError, ProviderInterest, ProviderOrder, ProviderFallback, ProviderPolicy, ProviderRegistry, ProviderEntry, ProviderSelection, ProviderLock, ProviderBackend, ProviderOpening};
#[cfg(feature = "hash")]
pub use umineko_helpers::provider::{HashProvider, HashProviderRequest, HashProviders};
#[cfg(feature = "crypto")]
pub use umineko_helpers::provider::{CipherProvider, CipherProviderRequest, CipherProviders, SignatureProvider, SignatureProviderRequest, SignatureProviders, ExchangeProvider, ExchangeProviderRequest, ExchangeProviders, KDFProvider, KDFProviderRequest, KDFProviderInputs, KDFProviders};
#[cfg(feature = "codec")]
pub use umineko_helpers::provider::{CodecProvider, CodecProviderRequest, CodecDirection, CodecProviders};
#[cfg(feature = "ip")]
pub use umineko_protocol_ip::{IPProvider, IPProviderRequest, IPProviders};
#[cfg(feature = "icmp")]
pub use umineko_protocol_icmp::{ICMPProvider, ICMPProviderRequest, ICMPProviders};
#[cfg(feature = "uds")]
pub use umineko_protocol_uds::{UDSProvider, UDSProviderRequest, UDSProviders};
#[cfg(feature = "tcp")]
pub use umineko_protocol_tcp::{TCPProvider, TCPProviderRequest, TCPProviders};
#[cfg(feature = "udp")]
pub use umineko_protocol_udp::{UDPProvider, UDPProviderRequest, UDPProviders};
#[cfg(feature = "tls")]
pub use umineko_protocol_tls::{TLSProvider, TLSProviderRequest, TLSProviders};
#[cfg(feature = "quic")]
pub use umineko_protocol_quic::{QUICProvider, QUICProviderRequest, QUICProviders};
#[cfg(feature = "http")]
pub use umineko_protocol_http::{HTTPProvider, HTTPProviderRequest, HTTPProviders};
#[cfg(feature = "dns")]
pub use umineko_protocol_dns::{DNSProvider, DNSProviderRequest, DNSProviders};

pub use bundle::{ProviderBundle};
pub use providers::{Providers};

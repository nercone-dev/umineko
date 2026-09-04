use alloc::{string::String, vec::Vec};
use crate::errors::TLSAlert;
use crate::types::{TLSVersion, TLSRole, TLSGroup, TLSCipher, TLSLimits};
use crate::helpers::handshake::TLSHandshakeState;
use crate::helpers::certificate::TLSCertificateChain;
use crate::helpers::alpn::TLSApplicationProtocol;
use crate::api::client::TLSClientConfig;
use crate::api::server::TLSServerConfig;
#[cfg(feature = "dtls")]
use crate::protocol::dtls::DTLSVersion;

use umineko_helpers::provider::{Provider, ProviderError, ProviderHandle, ProviderOpening, ProviderRegistry};

#[derive(Debug, Clone, Copy)]
pub enum TLSProviderRequest<'a> {
    Client { name: &'a str, config: &'a TLSClientConfig, limits: &'a TLSLimits },
    Server { config: &'a TLSServerConfig, limits: &'a TLSLimits },
    #[cfg(feature = "dtls")]
    DatagramClient { version: DTLSVersion, name: &'a str, config: &'a TLSClientConfig, limits: &'a TLSLimits },
    #[cfg(feature = "dtls")]
    DatagramServer { version: DTLSVersion, config: &'a TLSServerConfig, limits: &'a TLSLimits },
}

impl TLSProviderRequest<'_> {
    pub fn role(&self) -> TLSRole {
        match self {
            Self::Client { .. } => TLSRole::Client,
            Self::Server { .. } => TLSRole::Server,
            #[cfg(feature = "dtls")]
            Self::DatagramClient { .. } => TLSRole::Client,
            #[cfg(feature = "dtls")]
            Self::DatagramServer { .. } => TLSRole::Server,
        }
    }

    pub fn datagram(&self) -> bool {
        match self {
            Self::Client { .. } | Self::Server { .. } => false,
            #[cfg(feature = "dtls")]
            Self::DatagramClient { .. } | Self::DatagramServer { .. } => true,
        }
    }

    pub fn limits(&self) -> &TLSLimits {
        match self {
            Self::Client { limits, .. } => limits,
            Self::Server { limits, .. } => limits,
            #[cfg(feature = "dtls")]
            Self::DatagramClient { limits, .. } => limits,
            #[cfg(feature = "dtls")]
            Self::DatagramServer { limits, .. } => limits,
        }
    }
}

pub trait TLSProvider: Provider {
    fn supports(&self, request: &TLSProviderRequest<'_>) -> bool;

    fn open(&self, request: &TLSProviderRequest<'_>) -> Result<ProviderHandle, ProviderError>;

    fn absorb(&self, handle: ProviderHandle, data: &[u8]) -> Result<usize, ProviderError>;

    fn emit(&self, handle: ProviderHandle, output: &mut Vec<u8>) -> Result<usize, ProviderError>;

    fn handshake(&self, handle: ProviderHandle) -> Result<TLSHandshakeState, ProviderError>;

    fn send(&self, handle: ProviderHandle, data: &[u8]) -> Result<usize, ProviderError>;

    fn receive(&self, handle: ProviderHandle, data: &mut [u8]) -> Result<usize, ProviderError>;

    fn refresh(&self, handle: ProviderHandle) -> Result<(), ProviderError>;

    fn alert(&self, handle: ProviderHandle, alert: TLSAlert) -> Result<(), ProviderError>;

    fn close(&self, handle: ProviderHandle) -> Result<(), ProviderError>;

    fn send_early(&self, handle: ProviderHandle, data: &[u8]) -> Result<usize, ProviderError> {
        let _ = (handle, data);
        Err(ProviderError::Unsupported)
    }

    fn early_data_accepted(&self, handle: ProviderHandle) -> Result<bool, ProviderError> {
        let _ = handle;
        Ok(false)
    }

    fn select_certificate(&self, handle: ProviderHandle, chain: &TLSCertificateChain) -> Result<(), ProviderError>;

    fn select_application_protocol(&self, handle: ProviderHandle, protocol: &TLSApplicationProtocol) -> Result<(), ProviderError>;

    fn state(&self, handle: ProviderHandle) -> Result<TLSHandshakeState, ProviderError>;

    fn version(&self, handle: ProviderHandle) -> Result<Option<TLSVersion>, ProviderError>;

    fn role(&self, handle: ProviderHandle) -> Result<TLSRole, ProviderError>;

    fn cipher(&self, handle: ProviderHandle) -> Result<Option<TLSCipher>, ProviderError>;

    fn group(&self, handle: ProviderHandle) -> Result<Option<TLSGroup>, ProviderError>;

    fn application_protocol(&self, handle: ProviderHandle) -> Result<Option<String>, ProviderError>;

    fn server_name(&self, handle: ProviderHandle) -> Result<Option<String>, ProviderError>;

    fn peer_certificates(&self, handle: ProviderHandle) -> Result<Option<TLSCertificateChain>, ProviderError>;

    fn resumed(&self, handle: ProviderHandle) -> Result<bool, ProviderError>;

    #[cfg(feature = "dtls")]
    fn epoch(&self, handle: ProviderHandle) -> Result<u16, ProviderError> {
        let _ = handle;
        Err(ProviderError::Unsupported)
    }

    #[cfg(feature = "dtls")]
    fn cookie(&self, handle: ProviderHandle, peer: &[u8]) -> Result<[u8; 32], ProviderError> {
        let _ = (handle, peer);
        Err(ProviderError::Unsupported)
    }

    #[cfg(feature = "dtls")]
    fn retransmit(&self, handle: ProviderHandle) -> Result<(), ProviderError> {
        let _ = handle;
        Err(ProviderError::Unsupported)
    }
}

pub struct TLSProviders;

impl TLSProviders {
    pub fn global() -> &'static ProviderRegistry<dyn TLSProvider> {
        static REGISTRY: ProviderRegistry<dyn TLSProvider> = ProviderRegistry::new();
        &REGISTRY
    }

    pub fn open(request: &TLSProviderRequest<'_>) -> Result<Option<ProviderOpening<dyn TLSProvider>>, ProviderError> {
        Self::global().select(|provider| provider.supports(request)).open(|provider| provider.open(request))
    }
}

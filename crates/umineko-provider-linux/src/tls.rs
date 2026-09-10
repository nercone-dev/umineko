use umineko_provider::{TLSProvider, TLSProviderRequest, ProviderError, ProviderHandle};
use umineko_protocol_tls::{TLSVersion, TLSRole, TLSGroup, TLSCipher, TLSAlert};
use umineko_protocol_tls::helpers::{TLSHandshakeState, TLSCertificateChain, TLSApplicationProtocol};
use alloc::{string::String, vec::Vec};
use crate::linux::LinuxProvider;

impl TLSProvider for LinuxProvider {
    fn supports(&self, request: &TLSProviderRequest<'_>) -> bool {
        let _ = request;
        false
    }

    fn open(&self, request: &TLSProviderRequest<'_>) -> Result<ProviderHandle, ProviderError> {
        todo!()
    }

    fn absorb(&self, handle: ProviderHandle, data: &[u8]) -> Result<usize, ProviderError> {
        todo!()
    }

    fn emit(&self, handle: ProviderHandle, output: &mut Vec<u8>) -> Result<usize, ProviderError> {
        todo!()
    }

    fn handshake(&self, handle: ProviderHandle) -> Result<TLSHandshakeState, ProviderError> {
        todo!()
    }

    fn send(&self, handle: ProviderHandle, data: &[u8]) -> Result<usize, ProviderError> {
        todo!()
    }

    fn receive(&self, handle: ProviderHandle, data: &mut [u8]) -> Result<usize, ProviderError> {
        todo!()
    }

    fn refresh(&self, handle: ProviderHandle) -> Result<(), ProviderError> {
        todo!()
    }

    fn alert(&self, handle: ProviderHandle, alert: TLSAlert) -> Result<(), ProviderError> {
        todo!()
    }

    fn close(&self, handle: ProviderHandle) -> Result<(), ProviderError> {
        todo!()
    }

    fn select_certificate(&self, handle: ProviderHandle, chain: &TLSCertificateChain) -> Result<(), ProviderError> {
        todo!()
    }

    fn select_application_protocol(&self, handle: ProviderHandle, protocol: &TLSApplicationProtocol) -> Result<(), ProviderError> {
        todo!()
    }

    fn state(&self, handle: ProviderHandle) -> Result<TLSHandshakeState, ProviderError> {
        todo!()
    }

    fn version(&self, handle: ProviderHandle) -> Result<Option<TLSVersion>, ProviderError> {
        todo!()
    }

    fn role(&self, handle: ProviderHandle) -> Result<TLSRole, ProviderError> {
        todo!()
    }

    fn cipher(&self, handle: ProviderHandle) -> Result<Option<TLSCipher>, ProviderError> {
        todo!()
    }

    fn group(&self, handle: ProviderHandle) -> Result<Option<TLSGroup>, ProviderError> {
        todo!()
    }

    fn application_protocol(&self, handle: ProviderHandle) -> Result<Option<String>, ProviderError> {
        todo!()
    }

    fn server_name(&self, handle: ProviderHandle) -> Result<Option<String>, ProviderError> {
        todo!()
    }

    fn peer_certificates(&self, handle: ProviderHandle) -> Result<Option<TLSCertificateChain>, ProviderError> {
        todo!()
    }

    fn resumed(&self, handle: ProviderHandle) -> Result<bool, ProviderError> {
        todo!()
    }
}

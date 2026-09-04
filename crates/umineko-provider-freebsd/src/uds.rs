use umineko_provider::{UDSProvider, UDSProviderRequest, ProviderError, ProviderHandle, ProviderInterest};
use umineko_protocol_uds::UDSPath;
use umineko_protocol_uds::helpers::{UDSAncillary, UDSCredentials};
use core::task::{Context, Poll};
use crate::freebsd::FreeBSDProvider;

impl UDSProvider for FreeBSDProvider {
    fn supports(&self, request: &UDSProviderRequest<'_>) -> bool {
        let _ = request;
        false
    }

    fn open(&self, request: &UDSProviderRequest<'_>) -> Result<ProviderHandle, ProviderError> {
        todo!()
    }

    fn poll_ready(&self, handle: ProviderHandle, interest: ProviderInterest, cx: &mut Context<'_>) -> Poll<Result<(), ProviderError>> {
        todo!()
    }

    fn accept(&self, handle: ProviderHandle) -> Result<ProviderHandle, ProviderError> {
        todo!()
    }

    fn send(&self, handle: ProviderHandle, data: &[u8]) -> Result<usize, ProviderError> {
        todo!()
    }

    fn receive(&self, handle: ProviderHandle, data: &mut [u8]) -> Result<usize, ProviderError> {
        todo!()
    }

    fn send_to(&self, handle: ProviderHandle, remote: &UDSPath, data: &[u8]) -> Result<usize, ProviderError> {
        todo!()
    }

    fn receive_from(&self, handle: ProviderHandle, data: &mut [u8]) -> Result<(usize, UDSPath), ProviderError> {
        todo!()
    }

    fn send_with(&self, handle: ProviderHandle, data: &[u8], ancillary: &UDSAncillary) -> Result<usize, ProviderError> {
        todo!()
    }

    fn receive_with(&self, handle: ProviderHandle, data: &mut [u8]) -> Result<(usize, UDSAncillary), ProviderError> {
        todo!()
    }

    fn credentials(&self, handle: ProviderHandle) -> Result<UDSCredentials, ProviderError> {
        todo!()
    }

    fn shutdown(&self, handle: ProviderHandle) -> Result<(), ProviderError> {
        todo!()
    }

    fn close(&self, handle: ProviderHandle) -> Result<(), ProviderError> {
        todo!()
    }

    fn local(&self, handle: ProviderHandle) -> Result<UDSPath, ProviderError> {
        todo!()
    }

    fn remote(&self, handle: ProviderHandle) -> Result<UDSPath, ProviderError> {
        todo!()
    }
}

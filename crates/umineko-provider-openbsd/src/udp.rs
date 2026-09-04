use umineko_provider::{UDPProvider, UDPProviderRequest, ProviderError, ProviderHandle, ProviderInterest};
use umineko_protocol_udp::UDPEndpoint;
use core::task::{Context, Poll};
use crate::openbsd::OpenBSDProvider;

impl UDPProvider for OpenBSDProvider {
    fn supports(&self, request: &UDPProviderRequest<'_>) -> bool {
        let _ = request;
        false
    }

    fn open(&self, request: &UDPProviderRequest<'_>) -> Result<ProviderHandle, ProviderError> {
        todo!()
    }

    fn poll_ready(&self, handle: ProviderHandle, interest: ProviderInterest, cx: &mut Context<'_>) -> Poll<Result<(), ProviderError>> {
        todo!()
    }

    fn connect(&self, handle: ProviderHandle, remote: UDPEndpoint) -> Result<(), ProviderError> {
        todo!()
    }

    fn send_to(&self, handle: ProviderHandle, remote: UDPEndpoint, data: &[u8]) -> Result<usize, ProviderError> {
        todo!()
    }

    fn receive_from(&self, handle: ProviderHandle, data: &mut [u8]) -> Result<(usize, UDPEndpoint), ProviderError> {
        todo!()
    }

    fn send(&self, handle: ProviderHandle, data: &[u8]) -> Result<usize, ProviderError> {
        todo!()
    }

    fn receive(&self, handle: ProviderHandle, data: &mut [u8]) -> Result<usize, ProviderError> {
        todo!()
    }

    fn close(&self, handle: ProviderHandle) -> Result<(), ProviderError> {
        todo!()
    }

    fn local(&self, handle: ProviderHandle) -> Result<UDPEndpoint, ProviderError> {
        todo!()
    }

    fn remote(&self, handle: ProviderHandle) -> Result<UDPEndpoint, ProviderError> {
        todo!()
    }

    fn mtu(&self, handle: ProviderHandle) -> Result<usize, ProviderError> {
        todo!()
    }
}

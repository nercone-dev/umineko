use umineko_provider::{UDPProvider, UDPProviderRequest, ProviderError, ProviderHandle, ProviderInterest};
use umineko_protocol_udp::UDPEndpoint;
use core::task::{Context, Poll};
use umineko_provider_posix::POSIXProvider;
use crate::darwin::DarwinProvider;

impl UDPProvider for DarwinProvider {
    fn supports(&self, request: &UDPProviderRequest<'_>) -> bool {
        UDPProvider::supports(&POSIXProvider, request)
    }

    fn open(&self, request: &UDPProviderRequest<'_>) -> Result<ProviderHandle, ProviderError> {
        UDPProvider::open(&POSIXProvider, request)
    }

    fn poll_ready(&self, handle: ProviderHandle, interest: ProviderInterest, cx: &mut Context<'_>) -> Poll<Result<(), ProviderError>> {
        UDPProvider::poll_ready(&POSIXProvider, handle, interest, cx)
    }

    fn connect(&self, handle: ProviderHandle, remote: UDPEndpoint) -> Result<(), ProviderError> {
        UDPProvider::connect(&POSIXProvider, handle, remote)
    }

    fn send_to(&self, handle: ProviderHandle, remote: UDPEndpoint, data: &[u8]) -> Result<usize, ProviderError> {
        UDPProvider::send_to(&POSIXProvider, handle, remote, data)
    }

    fn receive_from(&self, handle: ProviderHandle, data: &mut [u8]) -> Result<(usize, UDPEndpoint), ProviderError> {
        UDPProvider::receive_from(&POSIXProvider, handle, data)
    }

    fn send(&self, handle: ProviderHandle, data: &[u8]) -> Result<usize, ProviderError> {
        UDPProvider::send(&POSIXProvider, handle, data)
    }

    fn receive(&self, handle: ProviderHandle, data: &mut [u8]) -> Result<usize, ProviderError> {
        UDPProvider::receive(&POSIXProvider, handle, data)
    }

    fn close(&self, handle: ProviderHandle) -> Result<(), ProviderError> {
        UDPProvider::close(&POSIXProvider, handle)
    }

    fn local(&self, handle: ProviderHandle) -> Result<UDPEndpoint, ProviderError> {
        UDPProvider::local(&POSIXProvider, handle)
    }

    fn remote(&self, handle: ProviderHandle) -> Result<UDPEndpoint, ProviderError> {
        UDPProvider::remote(&POSIXProvider, handle)
    }

    fn mtu(&self, handle: ProviderHandle) -> Result<usize, ProviderError> {
        UDPProvider::mtu(&POSIXProvider, handle)
    }
}

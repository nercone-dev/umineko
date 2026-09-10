use umineko_provider::{TCPProvider, TCPProviderRequest, ProviderError, ProviderHandle, ProviderInterest};
use umineko_protocol_tcp::{TCPEndpoint, TCPState};
use core::task::{Context, Poll};
use umineko_provider_posix::POSIXProvider;
use crate::openbsd::OpenBSDProvider;

impl TCPProvider for OpenBSDProvider {
    fn supports(&self, request: &TCPProviderRequest<'_>) -> bool {
        TCPProvider::supports(&POSIXProvider, request)
    }

    fn open(&self, request: &TCPProviderRequest<'_>) -> Result<ProviderHandle, ProviderError> {
        TCPProvider::open(&POSIXProvider, request)
    }

    fn poll_ready(&self, handle: ProviderHandle, interest: ProviderInterest, cx: &mut Context<'_>) -> Poll<Result<(), ProviderError>> {
        TCPProvider::poll_ready(&POSIXProvider, handle, interest, cx)
    }

    fn accept(&self, handle: ProviderHandle) -> Result<ProviderHandle, ProviderError> {
        TCPProvider::accept(&POSIXProvider, handle)
    }

    fn send(&self, handle: ProviderHandle, data: &[u8]) -> Result<usize, ProviderError> {
        TCPProvider::send(&POSIXProvider, handle, data)
    }

    fn receive(&self, handle: ProviderHandle, data: &mut [u8]) -> Result<usize, ProviderError> {
        TCPProvider::receive(&POSIXProvider, handle, data)
    }

    fn shutdown(&self, handle: ProviderHandle) -> Result<(), ProviderError> {
        TCPProvider::shutdown(&POSIXProvider, handle)
    }

    fn reset(&self, handle: ProviderHandle) -> Result<(), ProviderError> {
        TCPProvider::reset(&POSIXProvider, handle)
    }

    fn close(&self, handle: ProviderHandle) -> Result<(), ProviderError> {
        TCPProvider::close(&POSIXProvider, handle)
    }

    fn set_no_delay(&self, handle: ProviderHandle, no_delay: bool) -> Result<(), ProviderError> {
        TCPProvider::set_no_delay(&POSIXProvider, handle, no_delay)
    }

    fn set_keepalive(&self, handle: ProviderHandle, keepalive: bool) -> Result<(), ProviderError> {
        TCPProvider::set_keepalive(&POSIXProvider, handle, keepalive)
    }

    fn local(&self, handle: ProviderHandle) -> Result<TCPEndpoint, ProviderError> {
        TCPProvider::local(&POSIXProvider, handle)
    }

    fn remote(&self, handle: ProviderHandle) -> Result<TCPEndpoint, ProviderError> {
        TCPProvider::remote(&POSIXProvider, handle)
    }

    fn state(&self, handle: ProviderHandle) -> Result<TCPState, ProviderError> {
        TCPProvider::state(&POSIXProvider, handle)
    }

    fn segment_size(&self, handle: ProviderHandle) -> Result<u16, ProviderError> {
        TCPProvider::segment_size(&POSIXProvider, handle)
    }
}

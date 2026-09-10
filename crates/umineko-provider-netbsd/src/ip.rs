use umineko_provider::{IPProvider, IPProviderRequest, ProviderError, ProviderHandle, ProviderInterest};
use umineko_protocol_ip::{IPAddress, IPProtocol};
use core::task::{Context, Poll};
use umineko_provider_posix::POSIXProvider;
use crate::netbsd::NetBSDProvider;

impl IPProvider for NetBSDProvider {
    fn supports(&self, request: &IPProviderRequest<'_>) -> bool {
        IPProvider::supports(&POSIXProvider, request)
    }

    fn open(&self, request: &IPProviderRequest<'_>) -> Result<ProviderHandle, ProviderError> {
        IPProvider::open(&POSIXProvider, request)
    }

    fn poll_ready(&self, handle: ProviderHandle, interest: ProviderInterest, cx: &mut Context<'_>) -> Poll<Result<(), ProviderError>> {
        IPProvider::poll_ready(&POSIXProvider, handle, interest, cx)
    }

    fn send(&self, handle: ProviderHandle, destination: IPAddress, payload: &[u8]) -> Result<usize, ProviderError> {
        IPProvider::send(&POSIXProvider, handle, destination, payload)
    }

    fn receive(&self, handle: ProviderHandle, payload: &mut [u8]) -> Result<(usize, IPAddress), ProviderError> {
        IPProvider::receive(&POSIXProvider, handle, payload)
    }

    fn close(&self, handle: ProviderHandle) -> Result<(), ProviderError> {
        IPProvider::close(&POSIXProvider, handle)
    }

    fn local(&self, handle: ProviderHandle) -> Result<IPAddress, ProviderError> {
        IPProvider::local(&POSIXProvider, handle)
    }

    fn remote(&self, handle: ProviderHandle) -> Result<Option<IPAddress>, ProviderError> {
        IPProvider::remote(&POSIXProvider, handle)
    }

    fn protocol(&self, handle: ProviderHandle) -> Result<IPProtocol, ProviderError> {
        IPProvider::protocol(&POSIXProvider, handle)
    }

    fn mtu(&self, handle: ProviderHandle) -> Result<usize, ProviderError> {
        IPProvider::mtu(&POSIXProvider, handle)
    }
}

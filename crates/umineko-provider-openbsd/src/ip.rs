use umineko_provider::{IPProvider, IPProviderRequest, ProviderError, ProviderHandle, ProviderInterest};
use umineko_protocol_ip::{IPAddress, IPProtocol};
use core::task::{Context, Poll};
use crate::openbsd::OpenBSDProvider;

impl IPProvider for OpenBSDProvider {
    fn supports(&self, request: &IPProviderRequest<'_>) -> bool {
        let _ = request;
        false
    }

    fn open(&self, request: &IPProviderRequest<'_>) -> Result<ProviderHandle, ProviderError> {
        todo!()
    }

    fn poll_ready(&self, handle: ProviderHandle, interest: ProviderInterest, cx: &mut Context<'_>) -> Poll<Result<(), ProviderError>> {
        todo!()
    }

    fn send(&self, handle: ProviderHandle, destination: IPAddress, payload: &[u8]) -> Result<usize, ProviderError> {
        todo!()
    }

    fn receive(&self, handle: ProviderHandle, payload: &mut [u8]) -> Result<(usize, IPAddress), ProviderError> {
        todo!()
    }

    fn close(&self, handle: ProviderHandle) -> Result<(), ProviderError> {
        todo!()
    }

    fn local(&self, handle: ProviderHandle) -> Result<IPAddress, ProviderError> {
        todo!()
    }

    fn remote(&self, handle: ProviderHandle) -> Result<Option<IPAddress>, ProviderError> {
        todo!()
    }

    fn protocol(&self, handle: ProviderHandle) -> Result<IPProtocol, ProviderError> {
        todo!()
    }

    fn mtu(&self, handle: ProviderHandle) -> Result<usize, ProviderError> {
        todo!()
    }
}

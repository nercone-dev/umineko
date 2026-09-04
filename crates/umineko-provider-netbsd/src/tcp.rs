use umineko_provider::{TCPProvider, TCPProviderRequest, ProviderError, ProviderHandle, ProviderInterest};
use umineko_protocol_tcp::{TCPEndpoint, TCPState};
use core::task::{Context, Poll};
use crate::netbsd::NetBSDProvider;

impl TCPProvider for NetBSDProvider {
    fn supports(&self, request: &TCPProviderRequest<'_>) -> bool {
        let _ = request;
        false
    }

    fn open(&self, request: &TCPProviderRequest<'_>) -> Result<ProviderHandle, ProviderError> {
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

    fn shutdown(&self, handle: ProviderHandle) -> Result<(), ProviderError> {
        todo!()
    }

    fn reset(&self, handle: ProviderHandle) -> Result<(), ProviderError> {
        todo!()
    }

    fn close(&self, handle: ProviderHandle) -> Result<(), ProviderError> {
        todo!()
    }

    fn set_no_delay(&self, handle: ProviderHandle, no_delay: bool) -> Result<(), ProviderError> {
        todo!()
    }

    fn set_keepalive(&self, handle: ProviderHandle, keepalive: bool) -> Result<(), ProviderError> {
        todo!()
    }

    fn local(&self, handle: ProviderHandle) -> Result<TCPEndpoint, ProviderError> {
        todo!()
    }

    fn remote(&self, handle: ProviderHandle) -> Result<TCPEndpoint, ProviderError> {
        todo!()
    }

    fn state(&self, handle: ProviderHandle) -> Result<TCPState, ProviderError> {
        todo!()
    }

    fn segment_size(&self, handle: ProviderHandle) -> Result<u16, ProviderError> {
        todo!()
    }
}

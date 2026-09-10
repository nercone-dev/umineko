use umineko_provider::{HTTPProvider, HTTPProviderRequest, ProviderError, ProviderHandle};
use umineko_protocol_http::HTTPMessage;
use core::task::{Context, Poll};
use crate::wasi::WASIProvider;

impl HTTPProvider for WASIProvider {
    fn supports(&self, request: &HTTPProviderRequest<'_>) -> bool {
        let _ = request;
        false
    }

    fn open(&self, request: &HTTPProviderRequest<'_>) -> Result<ProviderHandle, ProviderError> {
        todo!()
    }

    fn poll_response(&self, handle: ProviderHandle, cx: &mut Context<'_>) -> Poll<Result<HTTPMessage, ProviderError>> {
        todo!()
    }

    fn poll_body(&self, handle: ProviderHandle, data: &mut [u8], cx: &mut Context<'_>) -> Poll<Result<usize, ProviderError>> {
        todo!()
    }

    fn cancel(&self, handle: ProviderHandle) -> Result<(), ProviderError> {
        todo!()
    }

    fn close(&self, handle: ProviderHandle) -> Result<(), ProviderError> {
        todo!()
    }
}

use umineko_provider::{ICMPProvider, ICMPProviderRequest, ProviderError, ProviderHandle, ProviderInterest};
use umineko_protocol_icmp::{ICMPType, ICMPCode};
use umineko_protocol_ip::IPAddress;
use core::task::{Context, Poll};
use crate::android::AndroidProvider;

impl ICMPProvider for AndroidProvider {
    fn supports(&self, request: &ICMPProviderRequest<'_>) -> bool {
        let _ = request;
        false
    }

    fn open(&self, request: &ICMPProviderRequest<'_>) -> Result<ProviderHandle, ProviderError> {
        todo!()
    }

    fn poll_ready(&self, handle: ProviderHandle, interest: ProviderInterest, cx: &mut Context<'_>) -> Poll<Result<(), ProviderError>> {
        todo!()
    }

    fn send(&self, handle: ProviderHandle, destination: IPAddress, kind: ICMPType, code: ICMPCode, payload: &[u8]) -> Result<usize, ProviderError> {
        todo!()
    }

    fn receive(&self, handle: ProviderHandle, payload: &mut [u8]) -> Result<(ICMPType, ICMPCode, usize, IPAddress), ProviderError> {
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
}

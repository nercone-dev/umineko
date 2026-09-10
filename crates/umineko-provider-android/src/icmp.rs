use umineko_provider::{ICMPProvider, ICMPProviderRequest, ProviderError, ProviderHandle, ProviderInterest};
use umineko_protocol_icmp::{ICMPType, ICMPCode};
use umineko_protocol_ip::IPAddress;
use core::task::{Context, Poll};
use umineko_provider_posix::POSIXProvider;
use crate::android::AndroidProvider;

impl ICMPProvider for AndroidProvider {
    fn supports(&self, request: &ICMPProviderRequest<'_>) -> bool {
        ICMPProvider::supports(&POSIXProvider, request)
    }

    fn open(&self, request: &ICMPProviderRequest<'_>) -> Result<ProviderHandle, ProviderError> {
        ICMPProvider::open(&POSIXProvider, request)
    }

    fn poll_ready(&self, handle: ProviderHandle, interest: ProviderInterest, cx: &mut Context<'_>) -> Poll<Result<(), ProviderError>> {
        ICMPProvider::poll_ready(&POSIXProvider, handle, interest, cx)
    }

    fn send(&self, handle: ProviderHandle, destination: IPAddress, kind: ICMPType, code: ICMPCode, payload: &[u8]) -> Result<usize, ProviderError> {
        ICMPProvider::send(&POSIXProvider, handle, destination, kind, code, payload)
    }

    fn receive(&self, handle: ProviderHandle, payload: &mut [u8]) -> Result<(ICMPType, ICMPCode, usize, IPAddress), ProviderError> {
        ICMPProvider::receive(&POSIXProvider, handle, payload)
    }

    fn close(&self, handle: ProviderHandle) -> Result<(), ProviderError> {
        ICMPProvider::close(&POSIXProvider, handle)
    }

    fn local(&self, handle: ProviderHandle) -> Result<IPAddress, ProviderError> {
        ICMPProvider::local(&POSIXProvider, handle)
    }

    fn remote(&self, handle: ProviderHandle) -> Result<Option<IPAddress>, ProviderError> {
        ICMPProvider::remote(&POSIXProvider, handle)
    }
}

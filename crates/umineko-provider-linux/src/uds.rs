use umineko_provider::{UDSProvider, UDSProviderRequest, ProviderError, ProviderHandle, ProviderInterest};
use umineko_protocol_uds::UDSPath;
use umineko_protocol_uds::helpers::{UDSAncillary, UDSCredentials};
use core::task::{Context, Poll};
use umineko_provider_posix::POSIXProvider;
use crate::linux::LinuxProvider;

impl UDSProvider for LinuxProvider {
    fn supports(&self, request: &UDSProviderRequest<'_>) -> bool {
        UDSProvider::supports(&POSIXProvider, request)
    }

    fn open(&self, request: &UDSProviderRequest<'_>) -> Result<ProviderHandle, ProviderError> {
        UDSProvider::open(&POSIXProvider, request)
    }

    fn poll_ready(&self, handle: ProviderHandle, interest: ProviderInterest, cx: &mut Context<'_>) -> Poll<Result<(), ProviderError>> {
        UDSProvider::poll_ready(&POSIXProvider, handle, interest, cx)
    }

    fn accept(&self, handle: ProviderHandle) -> Result<ProviderHandle, ProviderError> {
        UDSProvider::accept(&POSIXProvider, handle)
    }

    fn send(&self, handle: ProviderHandle, data: &[u8]) -> Result<usize, ProviderError> {
        UDSProvider::send(&POSIXProvider, handle, data)
    }

    fn receive(&self, handle: ProviderHandle, data: &mut [u8]) -> Result<usize, ProviderError> {
        UDSProvider::receive(&POSIXProvider, handle, data)
    }

    fn send_to(&self, handle: ProviderHandle, remote: &UDSPath, data: &[u8]) -> Result<usize, ProviderError> {
        UDSProvider::send_to(&POSIXProvider, handle, remote, data)
    }

    fn receive_from(&self, handle: ProviderHandle, data: &mut [u8]) -> Result<(usize, UDSPath), ProviderError> {
        UDSProvider::receive_from(&POSIXProvider, handle, data)
    }

    fn send_with(&self, handle: ProviderHandle, data: &[u8], ancillary: &UDSAncillary) -> Result<usize, ProviderError> {
        UDSProvider::send_with(&POSIXProvider, handle, data, ancillary)
    }

    fn receive_with(&self, handle: ProviderHandle, data: &mut [u8]) -> Result<(usize, UDSAncillary), ProviderError> {
        UDSProvider::receive_with(&POSIXProvider, handle, data)
    }

    fn credentials(&self, handle: ProviderHandle) -> Result<UDSCredentials, ProviderError> {
        UDSProvider::credentials(&POSIXProvider, handle)
    }

    fn shutdown(&self, handle: ProviderHandle) -> Result<(), ProviderError> {
        UDSProvider::shutdown(&POSIXProvider, handle)
    }

    fn close(&self, handle: ProviderHandle) -> Result<(), ProviderError> {
        UDSProvider::close(&POSIXProvider, handle)
    }

    fn local(&self, handle: ProviderHandle) -> Result<UDSPath, ProviderError> {
        UDSProvider::local(&POSIXProvider, handle)
    }

    fn remote(&self, handle: ProviderHandle) -> Result<UDSPath, ProviderError> {
        UDSProvider::remote(&POSIXProvider, handle)
    }
}

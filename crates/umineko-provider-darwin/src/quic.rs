use umineko_provider::{QUICProvider, QUICProviderRequest, ProviderError, ProviderHandle};
use umineko_protocol_quic::{QUICVersion, QUICRole, QUICConnectionID, QUICStreamID, QUICTransportParameters, QUICTransportError};
use umineko_protocol_quic::protocol::QUICStreamState;
use alloc::{string::String, vec::Vec};
use crate::darwin::DarwinProvider;

impl QUICProvider for DarwinProvider {
    fn supports(&self, request: &QUICProviderRequest<'_>) -> bool {
        let _ = request;
        false
    }

    fn open(&self, request: &QUICProviderRequest<'_>) -> Result<ProviderHandle, ProviderError> {
        todo!()
    }

    fn absorb(&self, handle: ProviderHandle, datagram: &[u8]) -> Result<(), ProviderError> {
        todo!()
    }

    fn emit(&self, handle: ProviderHandle, output: &mut Vec<u8>) -> Result<usize, ProviderError> {
        todo!()
    }

    fn timeout(&self, handle: ProviderHandle) -> Result<Option<f64>, ProviderError> {
        todo!()
    }

    fn handshake(&self, handle: ProviderHandle) -> Result<bool, ProviderError> {
        todo!()
    }

    fn open_stream(&self, handle: ProviderHandle, bidirectional: bool) -> Result<ProviderHandle, ProviderError> {
        todo!()
    }

    fn accept_stream(&self, handle: ProviderHandle) -> Result<ProviderHandle, ProviderError> {
        todo!()
    }

    fn stream_id(&self, stream: ProviderHandle) -> Result<QUICStreamID, ProviderError> {
        todo!()
    }

    fn stream_state(&self, stream: ProviderHandle) -> Result<QUICStreamState, ProviderError> {
        todo!()
    }

    fn stream_send(&self, stream: ProviderHandle, data: &[u8]) -> Result<usize, ProviderError> {
        todo!()
    }

    fn stream_receive(&self, stream: ProviderHandle, data: &mut [u8]) -> Result<usize, ProviderError> {
        todo!()
    }

    fn stream_finish(&self, stream: ProviderHandle) -> Result<(), ProviderError> {
        todo!()
    }

    fn stream_reset(&self, stream: ProviderHandle, error: u64) -> Result<(), ProviderError> {
        todo!()
    }

    fn stream_stop(&self, stream: ProviderHandle, error: u64) -> Result<(), ProviderError> {
        todo!()
    }

    fn probe(&self, handle: ProviderHandle) -> Result<(), ProviderError> {
        todo!()
    }

    fn migrate(&self, handle: ProviderHandle) -> Result<(), ProviderError> {
        todo!()
    }

    fn refresh(&self, handle: ProviderHandle) -> Result<(), ProviderError> {
        todo!()
    }

    fn close(&self, handle: ProviderHandle, error: QUICTransportError, reason: &[u8]) -> Result<(), ProviderError> {
        todo!()
    }

    fn version(&self, handle: ProviderHandle) -> Result<QUICVersion, ProviderError> {
        todo!()
    }

    fn role(&self, handle: ProviderHandle) -> Result<QUICRole, ProviderError> {
        todo!()
    }

    fn local_id(&self, handle: ProviderHandle) -> Result<QUICConnectionID, ProviderError> {
        todo!()
    }

    fn remote_id(&self, handle: ProviderHandle) -> Result<QUICConnectionID, ProviderError> {
        todo!()
    }

    fn parameters(&self, handle: ProviderHandle) -> Result<QUICTransportParameters, ProviderError> {
        todo!()
    }

    fn application_protocol(&self, handle: ProviderHandle) -> Result<Option<String>, ProviderError> {
        todo!()
    }

    fn established(&self, handle: ProviderHandle) -> Result<bool, ProviderError> {
        todo!()
    }
}

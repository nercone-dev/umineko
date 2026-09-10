use alloc::vec::Vec;
use crate::types::{HTTPVersion, HTTPRole, HTTPLimits};
use crate::api::server::HTTPHandler;

use umineko_protocol_tcp::api::server::TCPHandler;
use umineko_protocol_tcp::protocol::connection::TCPConnection;

#[cfg(feature = "uds")]
use umineko_protocol_uds::api::server::UDSHandler;
#[cfg(feature = "uds")]
use umineko_protocol_uds::protocol::base::UDSConnection;

#[cfg(feature = "http30")]
use umineko_protocol_quic::api::server::QUICHandler;
#[cfg(feature = "http30")]
use umineko_protocol_quic::protocol::base::QUICConnection;

#[derive(Debug, Clone)]
pub struct HTTPTCPHandler<H: HTTPHandler> {
    handler: H,
    versions: Vec<HTTPVersion>,
    role: HTTPRole,
    limits: HTTPLimits,
}

impl<H: HTTPHandler> HTTPTCPHandler<H> {
    pub fn new(handler: H, versions: Vec<HTTPVersion>, limits: HTTPLimits) -> Self {
        todo!()
    }

    pub fn detect(&self, data: &[u8]) -> Option<HTTPVersion> {
        todo!()
    }
}

impl<H: HTTPHandler> TCPHandler for HTTPTCPHandler<H> {
    async fn on_connection(&self, connection: &mut TCPConnection) {
        todo!()
    }
}

#[cfg(feature = "uds")]
#[derive(Debug, Clone)]
pub struct HTTPUDSHandler<H: HTTPHandler> {
    handler: H,
    versions: Vec<HTTPVersion>,
    role: HTTPRole,
    limits: HTTPLimits,
}

#[cfg(feature = "uds")]
impl<H: HTTPHandler> HTTPUDSHandler<H> {
    pub fn new(handler: H, versions: Vec<HTTPVersion>, limits: HTTPLimits) -> Self {
        todo!()
    }
}

#[cfg(feature = "uds")]
impl<H: HTTPHandler> UDSHandler for HTTPUDSHandler<H> {
    async fn on_connection(&self, connection: &mut UDSConnection) {
        todo!()
    }
}

#[cfg(feature = "http30")]
#[derive(Debug, Clone)]
pub struct HTTPQUICHandler<H: HTTPHandler> {
    handler: H,
    role: HTTPRole,
    limits: HTTPLimits,
}

#[cfg(feature = "http30")]
impl<H: HTTPHandler> HTTPQUICHandler<H> {
    pub fn new(handler: H, limits: HTTPLimits) -> Self {
        todo!()
    }
}

#[cfg(feature = "http30")]
impl<H: HTTPHandler> QUICHandler for HTTPQUICHandler<H> {
    async fn on_connection(&self, connection: &mut QUICConnection) {
        todo!()
    }
}

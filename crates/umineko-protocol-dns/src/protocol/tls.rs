use crate::errors::DNSError;
use crate::types::{DNSMessage, DNSLimits};
use crate::protocol::base::DNSTransport;

#[derive(Debug)]
pub struct DNSTLSConnection {
    limits: DNSLimits,
}

impl DNSTLSConnection {
    pub const TRANSPORT: DNSTransport = DNSTransport::TLS;

    pub async fn connect(name: &str, port: u16, limits: DNSLimits) -> Result<Self, DNSError> {
        todo!()
    }

    pub fn transport(&self) -> DNSTransport {
        Self::TRANSPORT
    }

    pub fn limits(&self) -> DNSLimits {
        self.limits
    }

    pub fn concurrency(&self) -> usize {
        todo!()
    }

    pub async fn send(&mut self, message: &DNSMessage) -> Result<(), DNSError> {
        todo!()
    }

    pub async fn receive(&mut self) -> Result<DNSMessage, DNSError> {
        todo!()
    }

    pub async fn query(&mut self, message: &DNSMessage) -> Result<DNSMessage, DNSError> {
        todo!()
    }

    pub async fn respond(&mut self, message: &DNSMessage) -> Result<(), DNSError> {
        todo!()
    }

    pub async fn close(&mut self) -> Result<(), DNSError> {
        todo!()
    }
}

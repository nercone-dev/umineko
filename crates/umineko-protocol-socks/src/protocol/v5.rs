use crate::errors::SOCKSError;
use crate::types::{SOCKSVersion, SOCKSCommand, SOCKSAddress, SOCKSReply, SOCKSLimits};
use crate::helpers::authentication::{SOCKSAuthentication, SOCKSCredentials};

#[derive(Debug)]
pub struct SOCKS5Connection {
    method: SOCKSAuthentication,
    credentials: Option<SOCKSCredentials>,
    bound: Option<(SOCKSAddress, u16)>,
    limits: SOCKSLimits,
}

impl SOCKS5Connection {
    pub const VERSION: SOCKSVersion = SOCKSVersion::V5;

    pub fn new(credentials: Option<SOCKSCredentials>, limits: SOCKSLimits) -> Self {
        todo!()
    }

    pub fn version(&self) -> SOCKSVersion {
        Self::VERSION
    }

    pub fn limits(&self) -> SOCKSLimits {
        self.limits
    }

    pub fn method(&self) -> SOCKSAuthentication {
        self.method
    }

    pub fn bound(&self) -> Option<(SOCKSAddress, u16)> {
        self.bound.clone()
    }

    pub async fn handshake(&mut self) -> Result<(), SOCKSError> {
        todo!()
    }

    pub async fn request(&mut self, command: SOCKSCommand, address: SOCKSAddress, port: u16) -> Result<(SOCKSAddress, u16), SOCKSError> {
        todo!()
    }

    pub async fn accept(&mut self, address: SOCKSAddress, port: u16) -> Result<(), SOCKSError> {
        todo!()
    }

    pub async fn reject(&mut self, reply: SOCKSReply) -> Result<(), SOCKSError> {
        todo!()
    }

    pub async fn send(&mut self, data: &[u8]) -> Result<usize, SOCKSError> {
        todo!()
    }

    pub async fn receive(&mut self, data: &mut [u8]) -> Result<usize, SOCKSError> {
        todo!()
    }

    pub async fn close(&mut self) -> Result<(), SOCKSError> {
        todo!()
    }
}

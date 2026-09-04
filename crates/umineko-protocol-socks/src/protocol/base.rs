use crate::errors::SOCKSError;
use crate::types::{SOCKSVersion, SOCKSCommand, SOCKSAddress, SOCKSReply, SOCKSLimits};

///
#[derive(Debug)]
pub enum SOCKSConnection {
    #[cfg(feature = "socks4")]
    V4(crate::protocol::v4::SOCKS4Connection),
    #[cfg(feature = "socks5")]
    V5(crate::protocol::v5::SOCKS5Connection),
}

impl SOCKSConnection {
    pub fn version(&self) -> SOCKSVersion {
        todo!()
    }

    pub fn limits(&self) -> SOCKSLimits {
        todo!()
    }

    pub fn bound(&self) -> Option<(SOCKSAddress, u16)> {
        todo!()
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

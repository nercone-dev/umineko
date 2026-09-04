use crate::errors::UDSError;
use crate::types::{UDSPath, UDSType, UDSLimits};
use crate::helpers::ancillary::UDSAncillary;
use crate::helpers::credentials::UDSCredentials;

///
#[derive(Debug)]
pub enum UDSConnection {
    Stream(crate::protocol::stream::UDSStreamConnection),
    Datagram(crate::protocol::datagram::UDSDatagramConnection),
    Seqpacket(crate::protocol::seqpacket::UDSSeqpacketConnection),
}

impl UDSConnection {
    pub fn kind(&self) -> UDSType {
        todo!()
    }

    pub fn local(&self) -> &UDSPath {
        todo!()
    }

    pub fn remote(&self) -> &UDSPath {
        todo!()
    }

    pub fn limits(&self) -> UDSLimits {
        todo!()
    }

    pub fn credentials(&self) -> Result<UDSCredentials, UDSError> {
        todo!()
    }

    pub async fn send(&mut self, data: &[u8]) -> Result<usize, UDSError> {
        todo!()
    }

    pub async fn receive(&mut self, data: &mut [u8]) -> Result<usize, UDSError> {
        todo!()
    }

    pub async fn send_with(&mut self, data: &[u8], ancillary: &UDSAncillary) -> Result<usize, UDSError> {
        todo!()
    }

    pub async fn receive_with(&mut self, data: &mut [u8]) -> Result<(usize, UDSAncillary), UDSError> {
        todo!()
    }

    pub async fn shutdown(&mut self) -> Result<(), UDSError> {
        todo!()
    }

    pub async fn close(&mut self) -> Result<(), UDSError> {
        todo!()
    }
}

#[derive(Debug)]
pub enum UDSListener {
    Stream(crate::protocol::stream::UDSStreamListener),
    Seqpacket(crate::protocol::seqpacket::UDSSeqpacketListener),
}

impl UDSListener {
    pub fn kind(&self) -> UDSType {
        todo!()
    }

    pub fn local(&self) -> &UDSPath {
        todo!()
    }

    pub async fn accept(&mut self) -> Result<UDSConnection, UDSError> {
        todo!()
    }

    pub async fn close(&mut self) -> Result<(), UDSError> {
        todo!()
    }
}

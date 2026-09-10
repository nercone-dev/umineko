use crate::errors::KerberosError;
use crate::types::{KerberosTransport, KerberosLimits};
use crate::protocol::messages::KerberosMessage;

#[derive(Debug)]
pub struct KerberosConnection {
    transport: KerberosTransport,
    limits: KerberosLimits,
}

impl KerberosConnection {
    pub async fn connect(server: &str, port: u16, transport: KerberosTransport, limits: KerberosLimits) -> Result<Self, KerberosError> {
        todo!()
    }

    pub fn transport(&self) -> KerberosTransport {
        self.transport
    }

    pub fn limits(&self) -> KerberosLimits {
        self.limits
    }

    pub async fn send(&mut self, message: &KerberosMessage) -> Result<(), KerberosError> {
        todo!()
    }

    pub async fn receive(&mut self) -> Result<KerberosMessage, KerberosError> {
        todo!()
    }

    pub async fn exchange(&mut self, message: &KerberosMessage) -> Result<KerberosMessage, KerberosError> {
        todo!()
    }

    pub async fn close(&mut self) -> Result<(), KerberosError> {
        todo!()
    }
}

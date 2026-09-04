use alloc::vec::Vec;
use crate::errors::MQTTError;
use crate::types::{MQTTVersion, MQTTQoS, MQTTReasonCode, MQTTLimits};
use crate::protocol::base::MQTTPacket;
use crate::helpers::topic::{MQTTTopic, MQTTFilter};
use crate::helpers::session::MQTTSession;

#[derive(Debug)]
pub struct MQTTV3Connection {
    session: MQTTSession,
    resumed: bool,
    limits: MQTTLimits,
}

impl MQTTV3Connection {
    pub const VERSION: MQTTVersion = MQTTVersion::V3_1_1;

    pub fn new(session: MQTTSession, limits: MQTTLimits) -> Self {
        todo!()
    }

    pub fn version(&self) -> MQTTVersion {
        Self::VERSION
    }

    pub fn limits(&self) -> MQTTLimits {
        self.limits
    }

    pub fn session(&self) -> &MQTTSession {
        &self.session
    }

    pub fn resumed(&self) -> bool {
        self.resumed
    }

    pub async fn connect(&mut self, client_id: &str, clean: bool) -> Result<(), MQTTError> {
        todo!()
    }

    pub async fn publish(&mut self, topic: &MQTTTopic, payload: &[u8], qos: MQTTQoS, retain: bool) -> Result<(), MQTTError> {
        todo!()
    }

    pub async fn subscribe(&mut self, filters: &[(MQTTFilter, MQTTQoS)]) -> Result<Vec<MQTTReasonCode>, MQTTError> {
        todo!()
    }

    pub async fn unsubscribe(&mut self, filters: &[MQTTFilter]) -> Result<Vec<MQTTReasonCode>, MQTTError> {
        todo!()
    }

    pub async fn receive(&mut self) -> Result<MQTTPacket, MQTTError> {
        todo!()
    }

    pub async fn accept(&mut self, qos: MQTTQoS) -> Result<(), MQTTError> {
        todo!()
    }

    pub async fn reject(&mut self, reason: MQTTReasonCode) -> Result<(), MQTTError> {
        todo!()
    }

    pub async fn ping(&mut self) -> Result<f64, MQTTError> {
        todo!()
    }

    pub async fn disconnect(&mut self, reason: MQTTReasonCode) -> Result<(), MQTTError> {
        todo!()
    }
}

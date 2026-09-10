use alloc::vec::Vec;
use crate::errors::MQTTError;
use crate::types::{MQTTVersion, MQTTQoS, MQTTReasonCode, MQTTLimits};
use crate::protocol::base::MQTTPacket;
use crate::helpers::topic::{MQTTTopic, MQTTFilter};
use crate::helpers::session::MQTTSession;

#[derive(Debug)]
pub struct MQTTV5Connection {
    session: MQTTSession,
    resumed: bool,
    limits: MQTTLimits,
}

impl MQTTV5Connection {
    pub const VERSION: MQTTVersion = MQTTVersion::V5_0;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MQTTProperty {
    PayloadFormat(u8),
    MessageExpiry(u32),
    TopicAlias(u16),
    ResponseTopic(MQTTTopic),
    CorrelationData(Vec<u8>),
    SubscriptionIdentifier(u32),
    SessionExpiry(u32),
    ReceiveMaximum(u16),
    MaximumPacketSize(u32),
    TopicAliasMaximum(u16),
    ReasonString(alloc::string::String),
    User { name: alloc::string::String, value: alloc::string::String },
    Unknown { kind: u8, data: Vec<u8> },
}

impl MQTTProperty {
    pub fn kind(&self) -> u8 {
        todo!()
    }

    pub fn encode(&self) -> Result<Vec<u8>, MQTTError> {
        todo!()
    }

    pub fn decode(data: &[u8]) -> Result<(Self, usize), MQTTError> {
        todo!()
    }
}

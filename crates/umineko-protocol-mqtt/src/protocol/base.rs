use alloc::vec::Vec;
use crate::errors::MQTTError;
use crate::types::{MQTTVersion, MQTTPacketType, MQTTQoS, MQTTReasonCode, MQTTLimits};
use crate::helpers::topic::{MQTTTopic, MQTTFilter};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MQTTPacket {
    pub kind: MQTTPacketType,
    pub identifier: Option<u16>,
    pub topic: Option<MQTTTopic>,
    pub qos: MQTTQoS,
    pub duplicate: bool,
    pub retain: bool,
    pub reason: Option<MQTTReasonCode>,
    pub payload: Vec<u8>,
}

impl MQTTPacket {
    pub const MINIMUM_SIZE: usize = 2;

    pub fn encode(&self, version: MQTTVersion, limits: MQTTLimits) -> Result<Vec<u8>, MQTTError> {
        todo!()
    }

    pub fn decode(data: &[u8], version: MQTTVersion, limits: MQTTLimits) -> Result<(Self, usize), MQTTError> {
        todo!()
    }

    pub fn encode_length(value: u32) -> Result<Vec<u8>, MQTTError> {
        todo!()
    }

    pub fn decode_length(data: &[u8]) -> Result<(u32, usize), MQTTError> {
        todo!()
    }
}

///
#[derive(Debug)]
pub enum MQTTConnection {
    #[cfg(feature = "mqtt31")]
    V3(crate::protocol::v3::MQTTV3Connection),
    #[cfg(feature = "mqtt50")]
    V5(crate::protocol::v5::MQTTV5Connection),
}

impl MQTTConnection {
    pub fn version(&self) -> MQTTVersion {
        todo!()
    }

    pub fn limits(&self) -> MQTTLimits {
        todo!()
    }

    pub fn resumed(&self) -> bool {
        todo!()
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

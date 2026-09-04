use alloc::{string::String, vec::Vec};
use crate::errors::MQTTError;
use crate::types::{MQTTQoS, MQTTLimits};
use crate::helpers::topic::{MQTTTopic, MQTTFilter};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MQTTSubscription {
    pub filter: MQTTFilter,
    pub qos: MQTTQoS,
    pub no_local: bool,
    pub retain_as_published: bool,
    pub identifier: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MQTTInflight {
    pub identifier: u16,
    pub topic: MQTTTopic,
    pub qos: MQTTQoS,
    pub payload: Vec<u8>,
    pub duplicate: bool,
    pub attempts: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MQTTSession {
    client_id: String,
    subscriptions: Vec<MQTTSubscription>,
    inflight: Vec<MQTTInflight>,
    queued: Vec<MQTTInflight>,
    next_identifier: u16,
    elapsed: f64,
    limits: MQTTLimits,
}

impl MQTTSession {
    pub fn new(client_id: &str, limits: MQTTLimits) -> Self {
        todo!()
    }

    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    pub fn next_identifier(&mut self) -> Result<u16, MQTTError> {
        todo!()
    }

    pub fn subscribe(&mut self, subscription: MQTTSubscription) -> Result<(), MQTTError> {
        todo!()
    }

    pub fn unsubscribe(&mut self, filter: &MQTTFilter) {
        todo!()
    }

    pub fn matching(&self, topic: &MQTTTopic) -> Vec<&MQTTSubscription> {
        todo!()
    }

    pub fn push(&mut self, entry: MQTTInflight) -> Result<(), MQTTError> {
        todo!()
    }

    pub fn acknowledge(&mut self, identifier: u16) -> Result<MQTTInflight, MQTTError> {
        todo!()
    }

    pub fn expired(&self, elapsed: f64) -> Vec<&MQTTInflight> {
        todo!()
    }

    pub fn clear(&mut self) {
        todo!()
    }
}

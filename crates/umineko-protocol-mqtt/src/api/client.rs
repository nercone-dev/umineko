use alloc::{string::String, vec::Vec};
use crate::errors::MQTTError;
use crate::types::{MQTTVersion, MQTTQoS, MQTTLimits};
use crate::helpers::topic::{MQTTTopic, MQTTFilter};
use crate::protocol::base::MQTTConnection;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MQTTClientConfig {
    pub versions: Vec<MQTTVersion>,
    pub client_id: String,
    pub username: Option<String>,
    pub password: Option<String>,

    pub clean_start: bool,
    pub will: Option<(MQTTTopic, Vec<u8>, MQTTQoS, bool)>,
    pub tls: bool,
}

impl Default for MQTTClientConfig {
    fn default() -> Self {
        Self {
            versions: [MQTTVersion::V5_0, MQTTVersion::V3_1_1].to_vec(),
            client_id: String::new(),
            username: None,
            password: None,

            clean_start: false,
            will: None,
            tls: true,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct MQTTClient {
    pub config: MQTTClientConfig,
    pub limits: MQTTLimits,
}

impl MQTTClient {
    pub fn new(config: MQTTClientConfig, limits: MQTTLimits) -> Self {
        todo!()
    }

    pub async fn connect(&self, host: &str, port: u16) -> Result<MQTTConnection, MQTTError> {
        todo!()
    }

    pub async fn publish(&self, topic: &MQTTTopic, payload: &[u8], qos: MQTTQoS, retain: bool) -> Result<(), MQTTError> {
        todo!()
    }

    pub async fn subscribe(&self, filters: &[(MQTTFilter, MQTTQoS)]) -> Result<(), MQTTError> {
        todo!()
    }

    pub async fn unsubscribe(&self, filters: &[MQTTFilter]) -> Result<(), MQTTError> {
        todo!()
    }
}


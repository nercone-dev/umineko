use alloc::vec::Vec;
use crate::errors::MQTTError;
use crate::types::{MQTTVersion, MQTTQoS, MQTTLimits};
use crate::protocol::base::MQTTConnection;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MQTTServerConfig {
    pub versions: Vec<MQTTVersion>,
    pub max_qos: MQTTQoS,

    pub retain: bool,
    pub shared_subscriptions: bool,
    pub anonymous: bool,
    pub require_tls: bool,
}

impl Default for MQTTServerConfig {
    fn default() -> Self {
        Self {
            versions: [MQTTVersion::V5_0, MQTTVersion::V3_1_1].to_vec(),
            max_qos: MQTTQoS::ExactlyOnce,

            retain: true,
            shared_subscriptions: true,
            anonymous: false,
            require_tls: true,
        }
    }
}

///
pub trait MQTTHandler {
    async fn on_connection(&self, connection: &mut MQTTConnection);
}

#[derive(Debug, Clone, Default)]
pub struct MQTTServer {
    pub config: MQTTServerConfig,
    pub limits: MQTTLimits,
}

impl MQTTServer {
    pub fn new(config: MQTTServerConfig, limits: MQTTLimits) -> Self {
        todo!()
    }

    pub async fn serve<H: MQTTHandler>(&self, handler: H) -> Result<(), MQTTError> {
        todo!()
    }

    pub fn run<H: MQTTHandler>(&self, handler: H, workers: usize) -> Result<(), MQTTError> {
        todo!()
    }
}

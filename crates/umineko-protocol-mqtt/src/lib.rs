//! MQTT.

#![no_std]
#![allow(async_fn_in_trait)]

extern crate alloc;

pub mod api {
    pub mod client;
    pub mod server;

    pub use client::{MQTTClient, MQTTClientConfig};
    pub use server::{MQTTServer, MQTTServerConfig, MQTTHandler};
}

pub mod helpers {
    pub mod topic;
    pub mod session;

    pub use topic::{MQTTTopic, MQTTFilter};
    pub use session::{MQTTSession, MQTTSubscription, MQTTInflight};
}

pub mod protocol {
    pub mod base;
    #[cfg(feature = "mqtt31")]
    pub mod v3;
    #[cfg(feature = "mqtt50")]
    pub mod v5;

    pub use base::{MQTTConnection, MQTTPacket};
    #[cfg(feature = "mqtt31")]
    pub use v3::{MQTTV3Connection};
    #[cfg(feature = "mqtt50")]
    pub use v5::{MQTTV5Connection, MQTTProperty};
}

pub mod errors;
pub mod types;

pub use errors::{MQTTError};
pub use types::{MQTTVersion, MQTTPacketType, MQTTQoS, MQTTReasonCode, MQTTLimits};

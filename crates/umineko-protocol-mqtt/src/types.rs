use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum MQTTVersion {
    V3_1_1,
    V5_0,
}

impl MQTTVersion {
    pub fn number(&self) -> u8 {
        match self {
            Self::V3_1_1 => 4,
            Self::V5_0 => 5,
        }
    }

    pub fn from_number(number: u8) -> Option<Self> {
        match number {
            4 => Some(Self::V3_1_1),
            5 => Some(Self::V5_0),
            _ => None,
        }
    }

    pub fn properties(&self) -> bool {
        matches!(self, Self::V5_0)
    }

    pub fn reason_codes(&self) -> bool {
        matches!(self, Self::V5_0)
    }

    pub fn topic_alias(&self) -> bool {
        matches!(self, Self::V5_0)
    }

    pub fn shared_subscriptions(&self) -> bool {
        matches!(self, Self::V5_0)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::V3_1_1 => "MQTT 3.1.1",
            Self::V5_0 => "MQTT 5.0",
        }
    }
}

impl fmt::Display for MQTTVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MQTTPacketType {
    Connect,
    ConnAck,
    Publish,
    PubAck,
    PubRec,
    PubRel,
    PubComp,
    Subscribe,
    SubAck,
    Unsubscribe,
    UnsubAck,
    PingReq,
    PingResp,
    Disconnect,
    Auth,
}

impl MQTTPacketType {
    pub fn number(&self) -> u8 {
        todo!()
    }

    pub fn from_number(number: u8) -> Option<Self> {
        todo!()
    }

    pub fn allowed(&self, version: MQTTVersion) -> bool {
        todo!()
    }

    pub fn requires_acknowledgement(&self) -> bool {
        todo!()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum MQTTQoS {
    AtMostOnce,
    AtLeastOnce,
    ExactlyOnce,
}

impl MQTTQoS {
    pub fn number(&self) -> u8 {
        match self {
            Self::AtMostOnce => 0,
            Self::AtLeastOnce => 1,
            Self::ExactlyOnce => 2,
        }
    }

    pub fn from_number(number: u8) -> Option<Self> {
        match number {
            0 => Some(Self::AtMostOnce),
            1 => Some(Self::AtLeastOnce),
            2 => Some(Self::ExactlyOnce),
            _ => None,
        }
    }

    pub fn requires_identifier(&self) -> bool {
        !matches!(self, Self::AtMostOnce)
    }

    pub fn effective(&self, other: Self) -> Self {
        todo!()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MQTTReasonCode {
    Success,
    NoMatchingSubscribers,
    UnspecifiedError,
    MalformedPacket,
    ProtocolError,
    UnsupportedProtocolVersion,
    ClientIdentifierNotValid,
    BadUserNameOrPassword,
    NotAuthorized,
    ServerUnavailable,
    ServerBusy,
    Banned,
    TopicNameInvalid,
    PacketTooLarge,
    QuotaExceeded,
    PayloadFormatInvalid,
    RetainNotSupported,
    QoSNotSupported,
    Unknown(u8),
}

impl MQTTReasonCode {
    pub fn number(&self) -> u8 {
        todo!()
    }

    pub fn from_number(number: u8) -> Self {
        todo!()
    }

    pub fn success(&self) -> bool {
        matches!(self, Self::Success | Self::NoMatchingSubscribers)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MQTTLimits {
    pub max_packet_size: u32,
    pub max_payload_size: u32,
    pub max_topic_length: u16,
    pub max_topic_levels: u8,
    pub max_property_count: u16,
    pub max_client_id_length: u16,

    pub max_connection_count: u64,
    pub max_subscription_count: u32,
    pub max_inflight_count: u16,
    pub max_queued_count: u32,
    pub max_topic_alias_count: u16,

    pub connect_timeout: f64,
    pub keepalive_interval: f64,
    pub read_timeout: f64,
    pub write_timeout: f64,
    pub retry_interval: f64,
    pub session_lifetime: f64,
}

impl Default for MQTTLimits {
    fn default() -> Self {
        Self {
            max_packet_size: 256 * 1024,
            max_payload_size: 256 * 1024,
            max_topic_length: 1024,
            max_topic_levels: 32,
            max_property_count: 64,
            max_client_id_length: 128,

            max_connection_count: 1024,
            max_subscription_count: 1024,
            max_inflight_count: 64,
            max_queued_count: 4096,
            max_topic_alias_count: 16,

            connect_timeout: 30.0,
            keepalive_interval: 60.0,
            read_timeout: 30.0,
            write_timeout: 30.0,
            retry_interval: 20.0,
            session_lifetime: 3600.0,
        }
    }
}

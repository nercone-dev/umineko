use alloc::string::String;
use core::fmt;
use crate::types::MQTTReasonCode;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MQTTError {
    Version,
    Packet,
    Property(String),
    Topic(String),
    State,
    Authentication,
    Rejected(MQTTReasonCode),
    Duplicate(u16),
    Limit,
    FlowControl,
    Closed,
    Transport,
    Timeout,
}

impl fmt::Display for MQTTError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl core::error::Error for MQTTError {}

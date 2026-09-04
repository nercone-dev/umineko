use alloc::{string::String, vec::Vec};
use core::fmt;
use crate::errors::MQTTError;
use crate::types::MQTTLimits;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MQTTTopic(String);

impl MQTTTopic {
    pub const SEPARATOR: char = '/';

    pub fn parse(text: &str, limits: MQTTLimits) -> Result<Self, MQTTError> {
        todo!()
    }

    pub fn as_str(&self) -> &str {
        todo!()
    }

    pub fn levels(&self) -> Vec<&str> {
        todo!()
    }

    pub fn reserved(&self) -> bool {
        todo!()
    }
}

impl fmt::Display for MQTTTopic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MQTTFilter(String);

impl MQTTFilter {
    pub const SINGLE_LEVEL: char = '+';
    pub const MULTI_LEVEL: char = '#';
    pub const SHARED_PREFIX: &'static str = "$share/";

    pub fn parse(text: &str, limits: MQTTLimits) -> Result<Self, MQTTError> {
        todo!()
    }

    pub fn as_str(&self) -> &str {
        todo!()
    }

    pub fn matches(&self, topic: &MQTTTopic) -> bool {
        todo!()
    }

    pub fn shared(&self) -> Option<&str> {
        todo!()
    }
}

impl fmt::Display for MQTTFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

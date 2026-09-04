use alloc::{string::String, vec::Vec};
use crate::errors::SMTPError;
use crate::types::SMTPAddress;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SMTPDeliveryAction {
    Delivered,
    Failed,
    Delayed,
    Relayed,
    Expanded,
}

impl SMTPDeliveryAction {
    pub fn as_str(&self) -> &'static str {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SMTPDeliveryStatus {
    pub recipient: SMTPAddress,
    pub action: SMTPDeliveryAction,
    pub status: String,
    pub diagnostic: Option<String>,
    pub remote: Option<String>,
}

impl SMTPDeliveryStatus {
    pub fn encode(&self) -> Result<Vec<u8>, SMTPError> {
        todo!()
    }

    pub fn decode(data: &[u8]) -> Result<Vec<Self>, SMTPError> {
        todo!()
    }
}

use alloc::vec::Vec;
use crate::errors::NDPError;
use crate::types::{NDPType, NDPOption};

use umineko_protocol_ip::IPAddress;

pub trait NDPMessage: Sized {
    fn kind(&self) -> NDPType;

    fn options(&self) -> &[NDPOption];

    fn validate(&self, hop_limit: u8, source: IPAddress) -> Result<(), NDPError>;

    fn encode(&self) -> Result<Vec<u8>, NDPError>;
    fn decode(data: &[u8]) -> Result<Self, NDPError>;
}

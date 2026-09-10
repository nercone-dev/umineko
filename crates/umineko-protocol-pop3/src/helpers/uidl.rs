use alloc::string::String;
use crate::errors::POP3Error;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct POP3UniqueID(String);

impl POP3UniqueID {
    pub const MAXIMUM_LENGTH: usize = 70;

    pub fn parse(text: &str) -> Result<Self, POP3Error> {
        todo!()
    }

    pub fn as_str(&self) -> &str {
        todo!()
    }
}

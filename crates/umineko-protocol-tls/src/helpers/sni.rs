use alloc::string::String;
use crate::errors::TLSError;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TLSServerName(String);

impl TLSServerName {
    pub const MAXIMUM_LENGTH: usize = 255;

    pub fn parse(text: &str) -> Result<Self, TLSError> {
        todo!()
    }

    pub fn as_str(&self) -> &str {
        todo!()
    }

    pub fn literal(&self) -> bool {
        todo!()
    }

    pub fn matches(&self, pattern: &str) -> bool {
        todo!()
    }
}

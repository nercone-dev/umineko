use alloc::{string::String, vec::Vec};
use crate::errors::FTPError;
use crate::types::FTPLimits;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FTPEntryKind {
    File,
    Directory,
    Current,
    Parent,
    Link,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FTPEntry {
    pub name: String,
    pub kind: FTPEntryKind,
    pub size: Option<u64>,
    pub modified: Option<String>,
    pub permissions: Option<String>,
    pub owner: Option<String>,
    pub group: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FTPListing {
    List,
    Names,
    Machine,
}

impl FTPListing {
    pub fn reliable(&self) -> bool {
        matches!(self, Self::Machine | Self::Names)
    }

    pub fn parse(&self, data: &[u8], limits: FTPLimits) -> Result<Vec<FTPEntry>, FTPError> {
        todo!()
    }

    pub fn encode(&self, entries: &[FTPEntry]) -> Result<Vec<u8>, FTPError> {
        todo!()
    }
}

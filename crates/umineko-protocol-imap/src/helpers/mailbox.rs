use alloc::{string::String, vec::Vec};
use crate::errors::IMAPError;
use crate::types::IMAPFlag;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IMAPMailboxAttribute {
    NoSelect,
    NoInferiors,
    HasChildren,
    HasNoChildren,
    Marked,
    Unmarked,
    Role(String),
    Unknown(String),
}

impl IMAPMailboxAttribute {
    pub fn as_str(&self) -> &str {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IMAPMailbox {
    pub name: String,
    pub delimiter: Option<char>,
    pub attributes: Vec<IMAPMailboxAttribute>,
    pub flags: Vec<IMAPFlag>,
    pub permanent_flags: Vec<IMAPFlag>,
    pub exists: u32,
    pub recent: u32,
    pub unseen: Option<u32>,
    pub next_uid: u32,
    pub uid_validity: u32,
    pub read_only: bool,
}

impl IMAPMailbox {
    pub const INBOX: &'static str = "INBOX";

    pub fn path(&self) -> Vec<&str> {
        todo!()
    }

    pub fn selectable(&self) -> bool {
        todo!()
    }

    pub fn matches(&self, pattern: &str) -> bool {
        todo!()
    }

    pub fn encode(&self) -> Result<Vec<u8>, IMAPError> {
        todo!()
    }
}

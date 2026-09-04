use alloc::{string::String, vec::Vec};
use crate::errors::IMAPError;
use crate::types::{IMAPFlag, IMAPLimits};
use crate::helpers::mailbox::IMAPMailbox;
use crate::helpers::search::IMAPSearchKey;
use crate::helpers::sequence::IMAPSequenceSet;
use crate::protocol::base::IMAPConnection;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IMAPClientConfig {
    pub username: Option<String>,
    pub password: Option<String>,
    pub mechanisms: Vec<String>,

    pub starttls: bool,
    pub require_starttls: bool,
    pub idle: bool,
    pub condstore: bool,
}

impl Default for IMAPClientConfig {
    fn default() -> Self {
        Self {
            username: None,
            password: None,
            mechanisms: Vec::new(),

            starttls: true,
            require_starttls: true,
            idle: true,
            condstore: true,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct IMAPClient {
    pub config: IMAPClientConfig,
    pub limits: IMAPLimits,
}

impl IMAPClient {
    pub fn new(config: IMAPClientConfig, limits: IMAPLimits) -> Self {
        todo!()
    }

    pub async fn connect(&self, host: &str, port: u16) -> Result<IMAPConnection, IMAPError> {
        todo!()
    }

    pub async fn list(&self, reference: &str, pattern: &str) -> Result<Vec<IMAPMailbox>, IMAPError> {
        todo!()
    }

    pub async fn select(&self, mailbox: &str, read_only: bool) -> Result<IMAPMailbox, IMAPError> {
        todo!()
    }

    pub async fn search(&self, key: &IMAPSearchKey) -> Result<IMAPSequenceSet, IMAPError> {
        todo!()
    }

    pub async fn fetch(&self, sequence: &IMAPSequenceSet, items: &[String]) -> Result<Vec<Vec<u8>>, IMAPError> {
        todo!()
    }

    pub async fn store(&self, sequence: &IMAPSequenceSet, flags: &[IMAPFlag], remove: bool) -> Result<(), IMAPError> {
        todo!()
    }

    pub async fn copy(&self, sequence: &IMAPSequenceSet, mailbox: &str) -> Result<(), IMAPError> {
        todo!()
    }

    pub async fn move_to(&self, sequence: &IMAPSequenceSet, mailbox: &str) -> Result<(), IMAPError> {
        todo!()
    }

    pub async fn append(&self, mailbox: &str, flags: &[IMAPFlag], data: &[u8]) -> Result<(), IMAPError> {
        todo!()
    }

    pub async fn expunge(&self) -> Result<Vec<u32>, IMAPError> {
        todo!()
    }
}


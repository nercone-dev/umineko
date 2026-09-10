use alloc::{string::String, vec::Vec};
use crate::errors::POP3Error;
use crate::types::POP3Limits;
use crate::helpers::uidl::POP3UniqueID;
use crate::protocol::base::POP3Connection;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct POP3ClientConfig {
    pub username: Option<String>,
    pub password: Option<String>,

    pub apop: bool,
    pub starttls: bool,
    pub require_starttls: bool,
    pub delete_after_retrieve: bool,
}

impl Default for POP3ClientConfig {
    fn default() -> Self {
        Self {
            username: None,
            password: None,

            apop: true,
            starttls: true,
            require_starttls: true,
            delete_after_retrieve: false,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct POP3Client {
    pub config: POP3ClientConfig,
    pub limits: POP3Limits,
}

impl POP3Client {
    pub fn new(config: POP3ClientConfig, limits: POP3Limits) -> Self {
        todo!()
    }

    pub async fn connect(&self, host: &str, port: u16) -> Result<POP3Connection, POP3Error> {
        todo!()
    }

    pub async fn stat(&self) -> Result<(u32, u64), POP3Error> {
        todo!()
    }

    pub async fn list(&self) -> Result<Vec<(u32, u64)>, POP3Error> {
        todo!()
    }

    pub async fn unique_ids(&self) -> Result<Vec<(u32, POP3UniqueID)>, POP3Error> {
        todo!()
    }

    pub async fn retrieve(&self, number: u32) -> Result<Vec<u8>, POP3Error> {
        todo!()
    }

    pub async fn top(&self, number: u32, lines: u32) -> Result<Vec<u8>, POP3Error> {
        todo!()
    }

    pub async fn delete(&self, number: u32) -> Result<(), POP3Error> {
        todo!()
    }

    pub async fn reset(&self) -> Result<(), POP3Error> {
        todo!()
    }
}


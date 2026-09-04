use alloc::{string::String, vec::Vec};
use crate::errors::POP3Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum POP3Command {
    USER(String),
    PASS(String),
    APOP { username: String, digest: String },
    STAT,
    LIST(Option<u32>),
    RETR(u32),
    DELE(u32),
    NOOP,
    RSET,
    TOP { number: u32, lines: u32 },
    UIDL(Option<u32>),
    CAPA,
    STLS,
    QUIT,
    Unknown { verb: String, argument: Option<String> },
}

impl POP3Command {
    pub fn verb(&self) -> &str {
        todo!()
    }

    pub fn allowed(&self, state: POP3State) -> bool {
        todo!()
    }

    pub fn encode(&self) -> Result<Vec<u8>, POP3Error> {
        todo!()
    }

    pub fn decode(line: &str) -> Result<Self, POP3Error> {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct POP3Response {
    pub success: bool,
    pub message: String,
    pub lines: Option<Vec<String>>,
}

impl POP3Response {
    pub const OK: &'static str = "+OK";
    pub const ERROR: &'static str = "-ERR";

    pub fn encode(&self) -> Result<Vec<u8>, POP3Error> {
        todo!()
    }

    pub fn decode(data: &[u8], multiline: bool) -> Result<(Self, usize), POP3Error> {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum POP3Capability {
    TOP,
    UIDL,
    STLS,
    SASL(Vec<String>),
    ExpireNever,
    Unknown(String),
}

impl POP3Capability {
    pub fn as_str(&self) -> &str {
        todo!()
    }

    pub fn from_name(name: &str) -> Self {
        todo!()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum POP3State {
    Authorization,
    Transaction,
    Update,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct POP3Limits {
    pub max_line_size: u32,
    pub max_message_size: u64,
    pub max_message_count: u32,

    pub max_connection_count: u64,
    pub max_authentication_attempts: u8,
    pub max_error_count: u8,

    pub connect_timeout: f64,
    pub greeting_timeout: f64,
    pub command_timeout: f64,
    pub idle_timeout: f64,
    pub close_timeout: f64,
}

impl Default for POP3Limits {
    fn default() -> Self {
        Self {
            max_line_size: 512,
            max_message_size: 32 * 1024 * 1024,
            max_message_count: 100_000,

            max_connection_count: 1024,
            max_authentication_attempts: 3,
            max_error_count: 10,

            connect_timeout: 30.0,
            greeting_timeout: 60.0,
            command_timeout: 120.0,
            idle_timeout: 600.0,
            close_timeout: 10.0,
        }
    }
}

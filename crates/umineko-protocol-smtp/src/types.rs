use alloc::{string::String, vec::Vec};
use core::fmt;
use crate::errors::SMTPError;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SMTPAddress {
    pub local: String,
    pub domain: String,
}

impl SMTPAddress {
    pub const MAXIMUM_LENGTH: usize = 320;

    pub fn parse(text: &str) -> Result<Self, SMTPError> {
        todo!()
    }

    pub fn null(&self) -> bool {
        todo!()
    }
}

impl fmt::Display for SMTPAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SMTPCommand {
    HELO(String),
    EHLO(String),
    MAIL { from: SMTPAddress, parameters: Vec<(String, Option<String>)> },
    RCPT { to: SMTPAddress, parameters: Vec<(String, Option<String>)> },
    DATA,
    BDAT { length: u64, last: bool },
    RSET,
    VRFY(String),
    EXPN(String),
    HELP(Option<String>),
    NOOP,
    QUIT,
    STARTTLS,
    AUTH { mechanism: String, initial: Option<String> },
    Unknown { verb: String, argument: Option<String> },
}

impl SMTPCommand {
    pub fn verb(&self) -> &str {
        todo!()
    }

    pub fn allowed(&self, state: SMTPState) -> bool {
        todo!()
    }

    pub fn encode(&self) -> Result<Vec<u8>, SMTPError> {
        todo!()
    }

    pub fn decode(line: &str) -> Result<Self, SMTPError> {
        todo!()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SMTPReplyCode(pub u16);

impl SMTPReplyCode {
    pub const READY: Self = Self(220);
    pub const CLOSING: Self = Self(221);
    pub const AUTHENTICATED: Self = Self(235);
    pub const OK: Self = Self(250);
    pub const START_MAIL_INPUT: Self = Self(354);
    pub const TRANSIENT_FAILURE: Self = Self(451);
    pub const SYNTAX_ERROR: Self = Self(500);
    pub const PERMANENT_FAILURE: Self = Self(550);

    pub fn success(&self) -> bool {
        (200..400).contains(&self.0)
    }

    pub fn transient(&self) -> bool {
        (400..500).contains(&self.0)
    }

    pub fn permanent(&self) -> bool {
        self.0 >= 500
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SMTPReply {
    pub code: SMTPReplyCode,
    pub lines: Vec<String>,
}

impl SMTPReply {
    pub fn encode(&self) -> Result<Vec<u8>, SMTPError> {
        todo!()
    }

    pub fn decode(data: &[u8]) -> Result<(Self, usize), SMTPError> {
        todo!()
    }

    pub fn extensions(&self) -> Vec<SMTPExtension> {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SMTPExtension {
    PIPELINING,
    SIZE(u64),
    STARTTLS,
    AUTH(Vec<String>),
    EIGHTBITMIME,
    CHUNKING,
    DSN,
    SMTPUTF8,
    Unknown { name: String, parameters: Vec<String> },
}

impl SMTPExtension {
    pub fn name(&self) -> &str {
        todo!()
    }

    pub fn decode(line: &str) -> Self {
        todo!()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SMTPState {
    Connected,
    Greeted,
    Authenticated,
    Mail,
    Recipient,
    Data,
    Closed,
}

impl SMTPState {
    pub fn in_transaction(&self) -> bool {
        matches!(self, Self::Mail | Self::Recipient | Self::Data)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SMTPLimits {
    pub max_line_size: u32,
    pub max_message_size: u64,
    pub max_header_size: u32,
    pub max_header_count: u16,
    pub max_recipient_count: u16,
    pub max_mime_depth: u8,

    pub max_connection_count: u64,
    pub max_transactions_per_connection: u32,
    pub max_error_count: u8,
    pub max_pipeline_count: u16,

    pub max_queue_count: u32,
    pub max_delivery_attempts: u32,

    pub connect_timeout: f64,
    pub greeting_timeout: f64,
    pub command_timeout: f64,
    pub data_timeout: f64,
    pub close_timeout: f64,
}

impl Default for SMTPLimits {
    fn default() -> Self {
        Self {
            max_line_size: 1000,
            max_message_size: 32 * 1024 * 1024,
            max_header_size: 128 * 1024,
            max_header_count: 512,
            max_recipient_count: 100,
            max_mime_depth: 16,

            max_connection_count: 1024,
            max_transactions_per_connection: 100,
            max_error_count: 10,
            max_pipeline_count: 32,

            max_queue_count: 16 * 1024,
            max_delivery_attempts: 10,

            connect_timeout: 30.0,
            greeting_timeout: 300.0,
            command_timeout: 300.0,
            data_timeout: 600.0,
            close_timeout: 10.0,
        }
    }
}

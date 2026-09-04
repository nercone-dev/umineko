use alloc::{string::String, vec::Vec};
use core::fmt;
use crate::errors::IMAPError;
use crate::helpers::sequence::IMAPSequenceSet;
use crate::helpers::search::IMAPSearchKey;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IMAPTag(String);

impl IMAPTag {
    pub const UNTAGGED: &'static str = "*";
    pub const CONTINUATION: &'static str = "+";

    pub fn new(index: u64) -> Self {
        todo!()
    }

    pub fn parse(text: &str) -> Result<Self, IMAPError> {
        todo!()
    }

    pub fn as_str(&self) -> &str {
        todo!()
    }
}

impl fmt::Display for IMAPTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IMAPCommand {
    Capability,
    Noop,
    Logout,
    StartTLS,
    Authenticate { mechanism: String, initial: Option<String> },
    Login { username: String, password: String },
    Select(String),
    Examine(String),
    Create(String),
    Delete(String),
    Rename { from: String, to: String },
    Subscribe(String),
    Unsubscribe(String),
    List { reference: String, pattern: String },
    Status { mailbox: String, items: Vec<String> },
    Append { mailbox: String, flags: Vec<IMAPFlag>, data: Vec<u8> },
    Check,
    Close,
    Expunge,
    Search(IMAPSearchKey),
    Fetch { sequence: IMAPSequenceSet, items: Vec<String>, uid: bool },
    Store { sequence: IMAPSequenceSet, flags: Vec<IMAPFlag>, remove: bool, uid: bool },
    Copy { sequence: IMAPSequenceSet, mailbox: String, uid: bool },
    Move { sequence: IMAPSequenceSet, mailbox: String, uid: bool },
    Idle,
    Unknown { verb: String, argument: Option<String> },
}

impl IMAPCommand {
    pub fn verb(&self) -> &str {
        todo!()
    }

    pub fn allowed(&self, state: IMAPState) -> bool {
        todo!()
    }

    pub fn encode(&self, tag: &IMAPTag) -> Result<Vec<u8>, IMAPError> {
        todo!()
    }

    pub fn decode(data: &[u8]) -> Result<(IMAPTag, Self, usize), IMAPError> {
        todo!()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IMAPStatus {
    Ok,
    No,
    Bad,
    Bye,
    Continuation,
}

impl IMAPStatus {
    pub fn success(&self) -> bool {
        matches!(self, Self::Ok)
    }

    pub fn as_str(&self) -> &'static str {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IMAPResponse {
    pub tag: Option<IMAPTag>,
    pub status: IMAPStatus,
    pub code: Option<String>,
    pub text: String,
    pub data: Vec<Vec<u8>>,
}

impl IMAPResponse {
    pub fn encode(&self) -> Result<Vec<u8>, IMAPError> {
        todo!()
    }

    pub fn decode(data: &[u8]) -> Result<(Self, usize), IMAPError> {
        todo!()
    }

    pub fn untagged(&self) -> bool {
        self.tag.is_none()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IMAPFlag {
    Seen,
    Answered,
    Flagged,
    Deleted,
    Draft,
    Recent,
    Keyword(String),
}

impl IMAPFlag {
    pub fn as_str(&self) -> &str {
        todo!()
    }

    pub fn from_name(name: &str) -> Self {
        todo!()
    }

    pub fn permanent(&self) -> bool {
        !matches!(self, Self::Recent)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IMAPCapability {
    IMAP4REV1,
    IMAP4REV2,
    StartTLS,
    LoginDisabled,
    Auth(String),
    Idle,
    CondStore,
    QResync,
    Move,
    Literal,
    Unknown(String),
}

impl IMAPCapability {
    pub fn as_str(&self) -> &str {
        todo!()
    }

    pub fn from_name(name: &str) -> Self {
        todo!()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IMAPState {
    NotAuthenticated,
    Authenticated,
    Selected,
    Logout,
}

impl IMAPState {
    pub fn authenticated(&self) -> bool {
        matches!(self, Self::Authenticated | Self::Selected)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct IMAPLimits {
    pub max_line_size: u32,
    pub max_literal_size: u64,
    pub max_message_size: u64,
    pub max_command_size: u32,
    pub max_response_size: u32,
    pub max_flag_count: u16,
    pub max_sequence_count: u32,
    pub max_search_depth: u8,

    pub max_connection_count: u64,
    pub max_mailbox_count: u32,
    pub max_error_count: u8,

    pub connect_timeout: f64,
    pub greeting_timeout: f64,
    pub command_timeout: f64,
    pub idle_timeout: f64,
    pub close_timeout: f64,
}

impl Default for IMAPLimits {
    fn default() -> Self {
        Self {
            max_line_size: 8 * 1024,
            max_literal_size: 32 * 1024 * 1024,
            max_message_size: 32 * 1024 * 1024,
            max_command_size: 64 * 1024,
            max_response_size: 1024 * 1024,
            max_flag_count: 256,
            max_sequence_count: 64 * 1024,
            max_search_depth: 16,

            max_connection_count: 1024,
            max_mailbox_count: 4096,
            max_error_count: 10,

            connect_timeout: 30.0,
            greeting_timeout: 60.0,
            command_timeout: 300.0,
            idle_timeout: 1740.0,
            close_timeout: 10.0,
        }
    }
}

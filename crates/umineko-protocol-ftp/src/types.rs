use alloc::{string::String, vec::Vec};
use crate::errors::FTPError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FTPCommand {
    USER(String),
    PASS(String),
    ACCT(String),
    CWD(String),
    CDUP,
    PWD,
    LIST(Option<String>),
    NLST(Option<String>),
    MLSD(Option<String>),
    MLST(Option<String>),
    RETR(String),
    STOR(String),
    APPE(String),
    DELE(String),
    MKD(String),
    RMD(String),
    RNFR(String),
    RNTO(String),
    SIZE(String),
    MDTM(String),
    REST(u64),
    TYPE(FTPDataType),
    MODE(FTPTransferMode),
    PASV,
    EPSV,
    PORT(String),
    EPRT(String),
    AUTH(String),
    PROT(char),
    PBSZ(u32),
    FEAT,
    OPTS { name: String, value: Option<String> },
    NOOP,
    ABOR,
    QUIT,
    Unknown { verb: String, argument: Option<String> },
}

impl FTPCommand {
    pub fn verb(&self) -> &str {
        todo!()
    }

    pub fn allowed(&self, state: FTPState) -> bool {
        todo!()
    }

    pub fn requires_data(&self) -> bool {
        todo!()
    }

    pub fn encode(&self) -> Result<Vec<u8>, FTPError> {
        todo!()
    }

    pub fn decode(line: &str) -> Result<Self, FTPError> {
        todo!()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FTPReplyCode(pub u16);

impl FTPReplyCode {
    pub const READY: Self = Self(220);
    pub const CLOSING: Self = Self(221);
    pub const TRANSFER_COMPLETE: Self = Self(226);
    pub const PASSIVE: Self = Self(227);
    pub const LOGGED_IN: Self = Self(230);
    pub const NEED_PASSWORD: Self = Self(331);
    pub const TRANSIENT_FAILURE: Self = Self(450);
    pub const SYNTAX_ERROR: Self = Self(500);
    pub const PERMANENT_FAILURE: Self = Self(550);

    pub fn success(&self) -> bool {
        (200..400).contains(&self.0)
    }

    pub fn intermediate(&self) -> bool {
        (300..400).contains(&self.0)
    }

    pub fn transient(&self) -> bool {
        (400..500).contains(&self.0)
    }

    pub fn permanent(&self) -> bool {
        self.0 >= 500
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FTPReply {
    pub code: FTPReplyCode,
    pub lines: Vec<String>,
}

impl FTPReply {
    pub fn encode(&self) -> Result<Vec<u8>, FTPError> {
        todo!()
    }

    pub fn decode(data: &[u8]) -> Result<(Self, usize), FTPError> {
        todo!()
    }

    pub fn endpoint(&self) -> Result<(String, u16), FTPError> {
        todo!()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FTPDataType {
    ASCII,
    Image,
}

impl FTPDataType {
    pub fn symbol(&self) -> char {
        match self {
            Self::ASCII => 'A',
            Self::Image => 'I',
        }
    }

    pub fn from_symbol(symbol: char) -> Option<Self> {
        todo!()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FTPTransferMode {
    Stream,
    Block,
    Compressed,
}

impl FTPTransferMode {
    pub fn symbol(&self) -> char {
        match self {
            Self::Stream => 'S',
            Self::Block => 'B',
            Self::Compressed => 'C',
        }
    }

    pub fn from_symbol(symbol: char) -> Option<Self> {
        todo!()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FTPState {
    Unauthenticated,
    NeedPassword,
    Authenticated,
    Transferring,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FTPLimits {
    pub max_line_size: u32,
    pub max_path_length: u16,
    pub max_listing_count: u32,
    pub max_file_size: u64,

    pub max_connection_count: u64,
    pub max_data_connection_count: u16,
    pub max_authentication_attempts: u8,
    pub max_error_count: u8,

    pub connect_timeout: f64,
    pub command_timeout: f64,
    pub data_timeout: f64,
    pub idle_timeout: f64,
    pub close_timeout: f64,
}

impl Default for FTPLimits {
    fn default() -> Self {
        Self {
            max_line_size: 4 * 1024,
            max_path_length: 4096,
            max_listing_count: 64 * 1024,
            max_file_size: 64 * 1024 * 1024 * 1024,

            max_connection_count: 1024,
            max_data_connection_count: 4,
            max_authentication_attempts: 3,
            max_error_count: 10,

            connect_timeout: 30.0,
            command_timeout: 120.0,
            data_timeout: 300.0,
            idle_timeout: 600.0,
            close_timeout: 10.0,
        }
    }
}

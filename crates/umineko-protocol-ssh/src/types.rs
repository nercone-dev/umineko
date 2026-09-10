use alloc::string::String;
use core::fmt;
use crate::errors::SSHError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SSHVersion {
    V2_0,
}

impl SSHVersion {
    pub const PREFIX: &'static str = "SSH-";

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::V2_0 => "2.0",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "2.0" => Some(Self::V2_0),
            _ => None,
        }
    }

    pub fn identification(&self, software: &str, comment: Option<&str>) -> String {
        todo!()
    }

    pub fn parse_identification(line: &str) -> Result<(Self, String), SSHError> {
        todo!()
    }
}

impl fmt::Display for SSHVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SSHRole {
    Client,
    Server,
}

impl SSHRole {
    pub fn peer(&self) -> Self {
        match self {
            Self::Client => Self::Server,
            Self::Server => Self::Client,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SSHMessageType {
    Disconnect,
    Ignore,
    Unimplemented,
    Debug,
    ServiceRequest,
    ServiceAccept,

    KexInit,
    NewKeys,
    KexEchange,

    UserAuthRequest,
    UserAuthFailure,
    UserAuthSuccess,
    UserAuthBanner,

    GlobalRequest,
    RequestSuccess,
    RequestFailure,

    ChannelOpen,
    ChannelOpenConfirmation,
    ChannelOpenFailure,
    ChannelWindowAdjust,
    ChannelData,
    ChannelExtendedData,
    ChannelEOF,
    ChannelClose,
    ChannelRequest,
    ChannelSuccess,
    ChannelFailure,

    Unknown(u8),
}

impl SSHMessageType {
    pub fn number(&self) -> u8 {
        todo!()
    }

    pub fn from_number(number: u8) -> Self {
        todo!()
    }

    pub fn allowed_during_kex(&self) -> bool {
        todo!()
    }

    pub fn allowed_before_authentication(&self) -> bool {
        todo!()
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SSHLimits {
    pub max_packet_size: u32,
    pub max_payload_size: u32,
    pub max_identification_size: u16,
    pub max_name_list_size: u32,
    pub max_public_key_size: u32,

    pub max_connection_count: u64,
    pub max_channel_count: u16,
    pub max_channel_window_size: u32,
    pub max_channel_packet_size: u32,

    pub max_authentication_attempts: u8,
    pub max_packets_per_key: u64,
    pub max_bytes_per_key: u64,

    pub connect_timeout: f64,
    pub identification_timeout: f64,
    pub kex_timeout: f64,
    pub authentication_timeout: f64,
    pub read_timeout: f64,
    pub write_timeout: f64,
    pub keepalive_interval: f64,
}

impl Default for SSHLimits {
    fn default() -> Self {
        Self {
            max_packet_size: 256 * 1024,
            max_payload_size: 32 * 1024,
            max_identification_size: 255,
            max_name_list_size: 64 * 1024,
            max_public_key_size: 16 * 1024,

            max_connection_count: 1024,
            max_channel_count: 64,
            max_channel_window_size: 2 * 1024 * 1024,
            max_channel_packet_size: 32 * 1024,

            max_authentication_attempts: 6,
            max_packets_per_key: 1 << 31,
            max_bytes_per_key: 1 << 30,

            connect_timeout: 30.0,
            identification_timeout: 30.0,
            kex_timeout: 60.0,
            authentication_timeout: 120.0,
            read_timeout: 30.0,
            write_timeout: 30.0,
            keepalive_interval: 60.0,
        }
    }
}

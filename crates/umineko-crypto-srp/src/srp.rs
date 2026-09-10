use alloc::vec::Vec;
use core::fmt;
use crate::errors::SRPError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SRPGroup {
    V1024,
    V1536,
    V2048,
    V3072,
    V4096,
    V6144,
    V8192,
}

impl SRPGroup {
    pub fn bits(&self) -> usize {
        match self {
            Self::V1024 => 1024,
            Self::V1536 => 1536,
            Self::V2048 => 2048,
            Self::V3072 => 3072,
            Self::V4096 => 4096,
            Self::V6144 => 6144,
            Self::V8192 => 8192,
        }
    }

    pub fn prime(&self) -> &'static [u8] {
        todo!()
    }

    pub fn generator(&self) -> u8 {
        match self {
            Self::V1024 | Self::V1536 | Self::V2048 => 2,
            Self::V3072 | Self::V4096 | Self::V6144 => 5,
            Self::V8192 => 19,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::V1024 => "SRP-1024",
            Self::V1536 => "SRP-1536",
            Self::V2048 => "SRP-2048",
            Self::V3072 => "SRP-3072",
            Self::V4096 => "SRP-4096",
            Self::V6144 => "SRP-6144",
            Self::V8192 => "SRP-8192",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "SRP-1024" => Some(Self::V1024),
            "SRP-1536" => Some(Self::V1536),
            "SRP-2048" => Some(Self::V2048),
            "SRP-3072" => Some(Self::V3072),
            "SRP-4096" => Some(Self::V4096),
            "SRP-6144" => Some(Self::V6144),
            "SRP-8192" => Some(Self::V8192),
            _ => None,
        }
    }
}

impl fmt::Display for SRPGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SRPVerifier {
    group: SRPGroup,
    salt: Vec<u8>,
    verifier: Vec<u8>,
}

impl SRPVerifier {
    pub fn new(group: SRPGroup, username: &[u8], password: &[u8], salt: &[u8]) -> Result<Self, SRPError> {
        todo!()
    }

    pub fn decode(group: SRPGroup, salt: &[u8], verifier: &[u8]) -> Result<Self, SRPError> {
        todo!()
    }

    pub fn group(&self) -> SRPGroup {
        self.group
    }

    pub fn salt(&self) -> &[u8] {
        &self.salt
    }

    pub fn encode(&self) -> Vec<u8> {
        self.verifier.clone()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SRPClient {
    group: SRPGroup,
    private: Vec<u8>,
    public: Vec<u8>,
}

impl SRPClient {
    pub fn new(group: SRPGroup, seed: &[u8]) -> Result<Self, SRPError> {
        todo!()
    }

    pub fn group(&self) -> SRPGroup {
        self.group
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public
    }

    pub fn premaster(&self, username: &[u8], password: &[u8], salt: &[u8], server: &[u8]) -> Result<Vec<u8>, SRPError> {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SRPServer {
    verifier: SRPVerifier,
    private: Vec<u8>,
    public: Vec<u8>,
}

impl SRPServer {
    pub fn new(verifier: SRPVerifier, seed: &[u8]) -> Result<Self, SRPError> {
        todo!()
    }

    pub fn group(&self) -> SRPGroup {
        self.verifier.group
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public
    }

    pub fn premaster(&self, client: &[u8]) -> Result<Vec<u8>, SRPError> {
        todo!()
    }
}

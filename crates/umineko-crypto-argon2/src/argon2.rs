use core::fmt;
use crate::errors::Argon2Error;

use umineko_helpers::provider::{KDFProviderInputs, KDFProviderRequest, KDFProviders};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Argon2Variant {
    D,
    I,
    ID,
}

impl Argon2Variant {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::D => "argon2d",
            Self::I => "argon2i",
            Self::ID => "argon2id",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "argon2d" => Some(Self::D),
            "argon2i" => Some(Self::I),
            "argon2id" => Some(Self::ID),
            _ => None,
        }
    }

    pub fn data_independent(&self) -> bool {
        matches!(self, Self::I | Self::ID)
    }
}

impl fmt::Display for Argon2Variant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Argon2 {
    pub variant: Argon2Variant,
    pub version: u32,
    pub memory: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for Argon2 {
    fn default() -> Self {
        Self { variant: Argon2Variant::ID, version: Self::VERSION_13, memory: 64 * 1024, iterations: 3, parallelism: 4 }
    }
}

impl Argon2 {
    pub const VERSION_10: u32 = 0x10;
    pub const VERSION_13: u32 = 0x13;
    pub const MINIMUM_SALT_SIZE: usize = 8;

    pub fn request(&self) -> KDFProviderRequest {
        KDFProviderRequest::new(self.variant.as_str()).with_memory(self.memory, self.iterations, self.parallelism, self.version)
    }

    pub fn derive(&self, password: &[u8], salt: &[u8], secret: &[u8], associated: &[u8], output: &mut [u8]) -> Result<(), Argon2Error> {
        if salt.len() < Self::MINIMUM_SALT_SIZE {
            return Err(Argon2Error::Salt);
        }
        match KDFProviders::derive(&self.request(), &KDFProviderInputs::new(password, salt).with_secret(secret).with_associated(associated), output)? {
            Some(()) => Ok(()),
            None => todo!(),
        }
    }

    pub fn verify(&self, password: &[u8], salt: &[u8], secret: &[u8], associated: &[u8], expected: &[u8]) -> Result<(), Argon2Error> {
        todo!()
    }
}

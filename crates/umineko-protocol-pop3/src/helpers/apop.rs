use alloc::string::String;
use crate::errors::POP3Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct APOPDigest(String);

impl APOPDigest {
    pub fn new(banner: &str, password: &str) -> Result<Self, POP3Error> {
        todo!()
    }

    pub fn as_str(&self) -> &str {
        todo!()
    }

    pub fn verify(&self, banner: &str, password: &str) -> Result<(), POP3Error> {
        todo!()
    }

    pub fn banner(hostname: &str, process: u32, counter: u64) -> String {
        todo!()
    }
}
